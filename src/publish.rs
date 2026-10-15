//! Workload publication uses the same Buildx candidate/scan/promotion protocol as
//! the toolkit release helper, without inheriting that helper's root credentials.
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::config::{Engine, LoadedConfig};
use crate::process::ProcessPlan;
use crate::source;

const SBOM_GENERATOR: &str = "docker.io/docker/buildkit-syft-scanner:stable-1@sha256:ae4f3b554449e7e25548e7d8ccc029d17357348e30c6e3df01b92bc93654d6a9";
const SEALED_FILES: &[&str] = &[
    "inputs.json",
    "source.tar",
    "build.stdout.log",
    "build.stderr.log",
    "build-metadata.json",
    "build-succeeded.json",
    "scan.json",
    "scanner.json",
    "index.json",
    "sbom.spdx.json",
    "provenance.json",
    "evidence.json",
];

pub struct PublishOptions<'a> {
    pub build_arg_file: Option<&'a Path>,
    pub ignore_unfixed: bool,
    pub os_only: bool,
    pub reuse_sealed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema: u32,
    source_sha: String,
    context_tree: String,
    config_path: Option<String>,
    config_sha256: Option<String>,
    context: String,
    engine: String,
    project: String,
    workload: String,
    component: String,
    dockerfile: String,
    platform: String,
    repository: String,
    tool_version: String,
    tool_binary_sha256: String,
    sbom_generator: String,
    build_arg_file: Option<String>,
    build_args_sha256: BTreeMap<String, String>,
    ignore_unfixed: bool,
    os_only: bool,
}

impl Inputs {
    fn same_except_tool(&self, other: &Self) -> bool {
        let mut current = self.clone();
        current.tool_version.clone_from(&other.tool_version);
        current
            .tool_binary_sha256
            .clone_from(&other.tool_binary_sha256);
        current == *other
    }
}

pub fn publish(
    loaded: &LoadedConfig,
    config_path: Option<&Path>,
    name: &str,
    revision: &str,
    evidence_root: &Path,
    options: PublishOptions<'_>,
    execute: bool,
) -> Result<()> {
    let workload = loaded.workload(name)?;
    ensure!(
        workload.engine == Engine::Docker,
        "publication currently requires Docker Buildx; Podman publication is not implemented"
    );
    ensure!(
        workload.platforms == ["linux/amd64"],
        "publication currently supports linux/amd64 only"
    );
    let registry = workload
        .registry
        .as_deref()
        .context("workload.registry is required for publication")?;
    validate_registry(registry)?;
    let snapshot = source::inspect(loaded, workload, config_path, revision)?;
    let (arg_path, build_args) = match options.build_arg_file {
        Some(path) => {
            let (relative, content) = committed_arg_file(&snapshot, path)?;
            (Some(relative), parse_arg_file(&content)?)
        }
        None => (None, BTreeMap::new()),
    };
    let repository = format!(
        "{registry}/{}/{}",
        loaded.config.project.name, workload.name
    );
    let target = format!("{repository}:{}", snapshot.revision);
    let candidate = format!("{repository}:candidate-{}", snapshot.revision);
    let inputs = Inputs {
        schema: 3,
        source_sha: snapshot.revision.clone(),
        context_tree: snapshot.tree.clone(),
        config_sha256: snapshot.config_sha256.clone(),
        config_path: snapshot
            .config_path
            .as_deref()
            .map(source_path)
            .transpose()?,
        context: source_path(&snapshot.context)?,
        engine: workload.engine.program().into(),
        project: loaded.config.project.name.clone(),
        workload: workload.name.clone(),
        component: workload.kind.as_str().into(),
        dockerfile: source_path(&snapshot.context.join(&snapshot.dockerfile))?,
        platform: workload.platforms[0].clone(),
        repository,
        tool_version: env!("CARGO_PKG_VERSION").into(),
        tool_binary_sha256: hash_file(&std::env::current_exe()?)?,
        sbom_generator: SBOM_GENERATOR.into(),
        build_arg_file: arg_path,
        build_args_sha256: arg_hashes(&build_args),
        ignore_unfixed: options.ignore_unfixed,
        os_only: options.os_only,
    };
    if !execute {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "result": "plan-only", "inputs": inputs, "candidate": candidate,
                "target": target, "evidence_root": evidence_root,
                "steps": ["archive exact Git context", "push attested candidate once",
                    "scan exact digest", "seal evidence", "promote same digest"]
            }))?
        );
        return Ok(());
    }
    // The same durable directory must be shared by all jobs publishing this target.
    // Registry administrators/other hosts can bypass this lock; consumers pin digests.
    let dir = state_directory(evidence_root, &snapshot.git_root, &target)?;
    let lock_path = dir.join("publish.lock");
    regular_or_absent(&lock_path)?;
    let mut lock_options = OpenOptions::new();
    lock_options
        .read(true)
        .write(true)
        .create(true)
        .truncate(false);
    private_options(&mut lock_options);
    let lock = lock_options.open(lock_path)?;
    lock.try_lock()
        .context("publication already running; retry using the same evidence directory")?;
    let input_path = dir.join("inputs.json");
    if input_path.exists() {
        let stored: Inputs = read_json(&input_path)?;
        ensure!(
            if options.reuse_sealed {
                stored.same_except_tool(&inputs)
            } else {
                stored == inputs
            },
            "existing publication state belongs to different source/config/tool inputs"
        );
        if options.reuse_sealed {
            return reuse_sealed(&dir, &stored, &target, &candidate, options);
        }
    } else {
        ensure!(
            !dir.join("checksums.json").exists(),
            "sealed state lacks inputs"
        );
        ensure!(
            !options.reuse_sealed,
            "no completed sealed publication to reuse"
        );
        write_json(&input_path, &inputs)?;
    }

    let seal = dir.join("checksums.json");
    if !seal.exists() {
        ensure!(
            !dir.join("complete").exists(),
            "completed publication has no evidence seal"
        );
        ensure!(
            lookup(&target)?.is_none(),
            "target exists without sealed evidence; refusing to rebuild or overwrite it"
        );
        let metadata = dir.join("build-metadata.json");
        if !metadata.exists() {
            ensure!(
                !dir.join("build-started").exists(),
                "previous build was interrupted without metadata; preserve candidate/state for reviewed recovery"
            );
            ensure!(
                lookup(&candidate)?.is_none(),
                "candidate exists without build metadata; refusing to overwrite it"
            );
            let archive = dir.join("source.tar");
            snapshot.archive(&archive)?;
            write_json(
                &dir.join("build-started"),
                &json!({"source_tar_sha256": hash_file(&archive)?}),
            )?;
            let mut build = ProcessPlan::new("docker")
                .arg("buildx")
                .arg("build")
                .arg("--push")
                .arg("--platform")
                .arg(&inputs.platform)
                .arg("--file")
                .arg(&snapshot.dockerfile)
                .arg("--label")
                .arg(format!("org.opencontainers.image.revision={revision}"))
                .arg("--label")
                .arg(format!(
                    "org.opencontainers.image.source-component={}",
                    inputs.component
                ))
                .arg("--attest")
                .arg(format!("type=sbom,generator={SBOM_GENERATOR}"))
                .arg("--provenance=mode=max")
                .arg("--metadata-file")
                .arg(&metadata)
                .arg("--tag")
                .arg(&candidate);
            for (name, value) in &build_args {
                build = build.arg("--build-arg").arg(format!("{name}={value}"));
            }
            let build = build.arg("-").input_file(archive.clone());
            let stdout_path = dir.join("build.stdout.log");
            let stderr_path = dir.join("build.stderr.log");
            let mut log_options = OpenOptions::new();
            log_options.write(true).create_new(true);
            private_options(&mut log_options);
            let stdout = log_options.open(&stdout_path)?;
            let stderr = log_options.open(&stderr_path)?;
            let status = build.run_to_files(stdout, stderr)?;
            if !status.success() {
                failure_excerpt("Buildx", &stderr_path);
                failure_excerpt("Buildx", &stdout_path);
            }
            ensure!(
                status.success(),
                "Buildx failed ({status}); inspect private {} and {}",
                stdout_path.display(),
                stderr_path.display()
            );
            write_json(
                &dir.join("build-succeeded.json"),
                &json!({
                    "metadata_sha256": hash_file(&metadata)?,
                    "source_tar_sha256": hash_file(&dir.join("source.tar"))?
                }),
            )?;
        }
        let started: Value = read_json(&dir.join("build-started"))?;
        ensure!(
            started["source_tar_sha256"].as_str() == Some(&hash_file(&dir.join("source.tar"))?),
            "archived source changed after build started"
        );
        let build = verified_build_metadata(&dir, &metadata)?;
        let digest = metadata_digest(&build)?;
        ensure!(
            lookup(&candidate)?.as_deref() == Some(digest),
            "candidate no longer matches build metadata"
        );
        let canonical = format!("{}@{digest}", inputs.repository);
        ProcessPlan::new("docker")
            .arg("pull")
            .arg(&canonical)
            .run_stdout_to_stderr()?;
        let inspect = ProcessPlan::new("docker")
            .arg("image")
            .arg("inspect")
            .arg(&canonical)
            .output()?;
        crate::verify_inspection(&inspect, revision, &inputs.component)?;
        let scanner = ProcessPlan::new("trivy")
            .arg("--version")
            .arg("--format")
            .arg("json")
            .output()?;
        let scanner: Value = serde_json::from_slice(&scanner)
            .context("Trivy did not return version/database metadata")?;
        ensure!(
            scanner["Version"].is_string(),
            "missing Trivy version metadata"
        );
        let scan = scan_plan(&canonical, options.ignore_unfixed, options.os_only).capture()?;
        // Keep the report even on a failed gate; do not expose arbitrary subprocess stderr.
        write_bytes(&dir.join("scan.json"), &scan.stdout)?;
        let scan_stderr = dir.join("scan.stderr.log");
        write_bytes(&scan_stderr, &scan.stderr)?;
        if !scan.status.success() && !scan_findings_summary(&scan.stdout, &canonical) {
            failure_excerpt("Trivy", &scan_stderr);
        }
        ensure!(
            scan.status.success(),
            "Trivy gate failed ({}); inspect scan.json in the private evidence directory",
            scan.status
        );
        let report: Value = serde_json::from_slice(&scan.stdout)?;
        validate_scan(&report, &canonical)?;
        // Fetch version again after scanning, since that scan may update the database.
        let scanner: Value = serde_json::from_slice(
            &ProcessPlan::new("trivy")
                .arg("--version")
                .arg("--format")
                .arg("json")
                .output()?,
        )?;
        ensure!(
            scanner["Version"].is_string()
                && scanner.pointer("/VulnerabilityDB/UpdatedAt").is_some(),
            "missing scanner version or vulnerability database timestamp"
        );
        write_json(&dir.join("scanner.json"), &scanner)?;
        let index = inspect_json(&canonical, None)?;
        let platform_digest = platform_digest(&index)?;
        let sbom = inspect_json(&canonical, Some("{{json .SBOM.SPDX}}"))?;
        ensure!(
            contains_key(&sbom, "spdxVersion"),
            "missing SPDX SBOM attestation"
        );
        let provenance = inspect_json(&canonical, Some("{{json .Provenance.SLSA}}"))?;
        ensure!(
            contains_key(&provenance, "buildType"),
            "missing provenance attestation"
        );
        write_json(&dir.join("index.json"), &index)?;
        write_json(&dir.join("sbom.spdx.json"), &sbom)?;
        write_json(&dir.join("provenance.json"), &provenance)?;
        write_json(
            &dir.join("evidence.json"),
            &json!({
                "schema": 2, "inputs": inputs, "canonical_ref": canonical,
                "image_digest": digest, "platform_manifest_digest": platform_digest,
                "source_archive_sha256": hash_file(&dir.join("source.tar"))?,
                "scan": {"result": "passed", "severities": ["HIGH", "CRITICAL"],
                    "ignore_unfixed": options.ignore_unfixed, "os_only": options.os_only,
                    "completed_unix_seconds": SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                    "scanner": scanner, "report": "scan.json"},
                "sbom": "sbom.spdx.json", "provenance": "provenance.json"
            }),
        )?;
        let hashes: BTreeMap<_, _> = SEALED_FILES
            .iter()
            .map(|name| Ok((name.to_string(), hash_file(&dir.join(name))?)))
            .collect::<Result<_>>()?;
        write_json(&seal, &hashes)?;
    }
    verify_seal(&dir)?;
    let evidence: Value = read_json(&dir.join("evidence.json"))?;
    let digest = evidence["image_digest"]
        .as_str()
        .context("evidence has no digest")?;
    validate_digest(digest)?;
    let canonical = format!("{}@{digest}", inputs.repository);
    ensure!(
        evidence["inputs"] == serde_json::to_value(&inputs)?
            && evidence["canonical_ref"] == canonical,
        "sealed evidence does not match this publication"
    );
    match lookup(&target)? {
        Some(existing) => ensure!(
            existing == digest,
            "immutable target differs from approved digest"
        ),
        None => {
            ensure!(
                !dir.join("complete").exists(),
                "completed target disappeared; refusing automatic recreation"
            );
            ProcessPlan::new("docker")
                .arg("buildx")
                .arg("imagetools")
                .arg("create")
                .arg("--tag")
                .arg(&target)
                .arg(&canonical)
                .run_stdout_to_stderr()?;
        }
    }
    ensure!(
        lookup(&target)?.as_deref() == Some(digest),
        "promotion changed the verified digest"
    );
    write_json(&dir.join("complete"), &json!({"canonical_ref": canonical}))?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"result":"published",
        "canonical_ref":canonical, "evidence":dir.join("evidence.json"),
        "evidence_sha256":hash_file(&dir.join("evidence.json"))?}))?
    );
    Ok(())
}

fn reuse_sealed(
    dir: &Path,
    stored: &Inputs,
    target: &str,
    candidate: &str,
    options: PublishOptions<'_>,
) -> Result<()> {
    ensure!(
        dir.join("checksums.json").exists() && dir.join("complete").exists(),
        "reuse requires completed sealed publication"
    );
    verify_seal(dir)?;
    let evidence: Value = read_json(&dir.join("evidence.json"))?;
    let digest = evidence["image_digest"]
        .as_str()
        .context("evidence has no digest")?;
    validate_digest(digest)?;
    let canonical = format!("{}@{digest}", stored.repository);
    ensure!(
        evidence["inputs"] == serde_json::to_value(stored)?
            && evidence["canonical_ref"] == canonical,
        "sealed evidence does not match original publication"
    );
    let complete: Value = read_json(&dir.join("complete"))?;
    ensure!(
        complete["canonical_ref"] == canonical,
        "completed publication does not match sealed digest"
    );
    ensure!(
        lookup(candidate)?.as_deref() == Some(digest),
        "candidate no longer matches sealed digest"
    );
    ensure!(
        lookup(target)?.as_deref() == Some(digest),
        "immutable target differs from approved digest"
    );

    // Local images may be removed; the sealed registry
    // artifact is not. Restore exactly that digest before a Docker-only scan.
    ProcessPlan::new("docker")
        .arg("pull")
        .arg(&canonical)
        .run_stdout_to_stderr()?;

    let attempt = format!(
        "reuse-{}-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos(),
        std::process::id()
    );
    let report_path = dir.join(format!("{attempt}-scan.json"));
    let stderr_path = dir.join(format!("{attempt}-scan.stderr.log"));
    let scan = scan_plan(&canonical, options.ignore_unfixed, options.os_only).capture()?;
    write_bytes(&report_path, &scan.stdout)?;
    write_bytes(&stderr_path, &scan.stderr)?;
    if !scan.status.success() && !scan_findings_summary(&scan.stdout, &canonical) {
        failure_excerpt("Trivy", &stderr_path);
    }
    ensure!(
        scan.status.success(),
        "Trivy gate failed ({}); inspect the private retry scan report",
        scan.status
    );
    let report: Value = serde_json::from_slice(&scan.stdout)?;
    validate_scan(&report, &canonical)?;
    let scanner: Value = serde_json::from_slice(
        &ProcessPlan::new("trivy")
            .arg("--version")
            .arg("--format")
            .arg("json")
            .output()?,
    )?;
    ensure!(
        scanner["Version"].is_string() && scanner.pointer("/VulnerabilityDB/UpdatedAt").is_some(),
        "missing scanner version or vulnerability database timestamp"
    );
    let scanner_path = dir.join(format!("{attempt}-scanner.json"));
    write_json(&scanner_path, &scanner)?;
    ensure!(
        lookup(candidate)?.as_deref() == Some(digest) && lookup(target)?.as_deref() == Some(digest),
        "candidate or immutable target changed during the current scan"
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "result": "published", "reused_sealed": true,
            "canonical_ref": canonical, "evidence": dir.join("evidence.json"),
            "evidence_sha256": hash_file(&dir.join("evidence.json"))?,
            "current_scan": report_path, "current_scan_sha256": hash_file(&report_path)?,
            "current_scanner": scanner_path,
            "scan_policy": {"ignore_unfixed": options.ignore_unfixed, "os_only": options.os_only}
        }))?
    );
    Ok(())
}

// Report only schema fields with fixed vocabulary or strictly shaped advisory IDs.
// Descriptions, package names, URLs and other free-form scanner data remain private.
fn scan_findings_summary(bytes: &[u8], canonical: &str) -> bool {
    let Ok(report) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    if report["ArtifactName"].as_str() != Some(canonical) {
        return false;
    }
    let Some(results) = report["Results"].as_array() else {
        return false;
    };
    let mut count = 0_usize;
    let mut ids = Vec::new();
    for result in results {
        let Some(vulnerabilities) = result["Vulnerabilities"].as_array() else {
            continue;
        };
        for finding in vulnerabilities {
            let Some(severity @ ("HIGH" | "CRITICAL")) = finding["Severity"].as_str() else {
                continue;
            };
            count += 1;
            if ids.len() < 20
                && let Some(id) = finding["VulnerabilityID"]
                    .as_str()
                    .filter(|id| safe_advisory_id(id))
            {
                ids.push(format!("{id} ({severity})"));
            }
        }
    }
    if count == 0 {
        return false;
    }
    eprintln!("Trivy report: {count} HIGH/CRITICAL finding(s); full report retained privately");
    for id in ids {
        eprintln!("  {id}");
    }
    true
}

fn safe_advisory_id(id: &str) -> bool {
    let parts: Vec<_> = id.split('-').collect();
    match parts.as_slice() {
        ["CVE" | "RUSTSEC", year, number] => {
            year.len() == 4
                && year.bytes().all(|b| b.is_ascii_digit())
                && number.len() >= 4
                && number.len() <= 8
                && number.bytes().all(|b| b.is_ascii_digit())
        }
        ["GHSA", a, b, c] => [a, b, c].iter().all(|part| {
            part.len() == 4
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        }),
        _ => false,
    }
}

// Child output is untrusted (and may contain build args or Actions workflow commands).
// Only simple error lines are safe enough for the public CI log; full logs stay private.
fn failure_excerpt(phase: &str, path: &Path) {
    let Some(bytes) = (|| -> Option<(bool, Vec<u8>)> {
        let mut file = File::open(path).ok()?;
        let len = file.metadata().ok()?.len();
        file.seek(SeekFrom::Start(len.saturating_sub(64 * 1024)))
            .ok()?;
        let mut bytes = Vec::new();
        file.take(64 * 1024).read_to_end(&mut bytes).ok()?;
        Some((len > 64 * 1024, bytes))
    })() else {
        eprintln!("{phase}: diagnostic log unavailable; inspect private evidence");
        return;
    };
    let tail = if bytes.0 {
        bytes
            .1
            .splitn(2, |byte| *byte == b'\n')
            .nth(1)
            .unwrap_or(&[])
    } else {
        &bytes.1
    };
    let decoded = String::from_utf8_lossy(tail);
    let lines: Vec<_> = decoded
        .lines()
        .rev()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            (lower.contains("error") || lower.contains("fatal") || lower.contains("failed"))
                && ![
                    "password",
                    "passwd",
                    "secret",
                    "token",
                    "credential",
                    "authorization",
                    "cookie",
                    "api_key",
                    "apikey",
                    "access_key",
                    "private key",
                    "database_url",
                    "redis_url",
                    "://",
                    "::",
                    "@",
                    "?",
                    "=",
                ]
                .iter()
                .any(|word| lower.contains(word))
                && line.bytes().all(|byte| (b' '..=b'~').contains(&byte))
                && !line
                    .split(|ch: char| !(ch.is_ascii_alphanumeric() || "_+-/".contains(ch)))
                    .any(|part| part.len() >= 24)
                && line.len() <= 500
        })
        .take(20)
        .collect();
    if lines.is_empty() {
        eprintln!("{phase}: failure output withheld; inspect private evidence");
        return;
    }
    // Suppress GitHub workflow command parsing even if a future filter is loosened.
    let mut marker = [0_u8; 16];
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        if File::open("/dev/urandom")
            .and_then(|mut file| file.read_exact(&mut marker))
            .is_err()
        {
            eprintln!("{phase}: failure output withheld; secure command boundary unavailable");
            return;
        }
        eprintln!("::stop-commands::{}", hex_marker(&marker));
    }
    eprintln!("{phase}: diagnostic excerpt (full log retained privately):");
    for line in lines.into_iter().rev() {
        eprintln!("{line}");
    }
    if std::env::var_os("GITHUB_ACTIONS").is_some() {
        eprintln!("::{}::", hex_marker(&marker));
    }
}

fn hex_marker(bytes: &[u8; 16]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn committed_arg_file(snapshot: &source::Snapshot, path: &Path) -> Result<(String, Vec<u8>)> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    ensure!(
        !absolute
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir)),
        "build arg file path may not contain parent traversal"
    );
    for part in absolute.ancestors() {
        if let Ok(metadata) = fs::symlink_metadata(part) {
            ensure!(
                !metadata.file_type().is_symlink(),
                "build arg file path may not use symlinks"
            );
        }
    }
    let absolute = fs::canonicalize(&absolute).context("cannot open build arg file")?;
    ensure!(absolute.is_file(), "build arg file must be a regular file");
    let context = snapshot.git_root.join(&snapshot.context);
    ensure!(
        absolute.starts_with(&context) && absolute != context,
        "build arg file must be inside the committed build context"
    );
    let relative = source_path(absolute.strip_prefix(&snapshot.git_root)?)?;
    let listing = Command::new("git")
        .args(["ls-tree", "-z", &snapshot.revision, "--", &relative])
        .current_dir(&snapshot.git_root)
        .output()
        .context("cannot inspect committed build arg file")?;
    ensure!(
        listing.status.success(),
        "cannot inspect committed build arg file"
    );
    let expected = relative.as_bytes();
    let entries: Vec<_> = listing
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
        .filter(|entry| {
            entry
                .iter()
                .position(|byte| *byte == b'\t')
                .is_some_and(|index| &entry[index + 1..] == expected)
        })
        .collect();
    ensure!(
        entries.len() == 1,
        "build arg file is not committed at this revision"
    );
    ensure!(
        entries[0].starts_with(b"100644 blob ") || entries[0].starts_with(b"100755 blob "),
        "build arg file must be a committed regular file"
    );
    let blob = Command::new("git")
        .arg("show")
        .arg(format!("{}:{relative}", snapshot.revision))
        .current_dir(&snapshot.git_root)
        .output()
        .context("cannot read committed build arg file")?;
    ensure!(
        blob.status.success(),
        "cannot read committed build arg file"
    );
    Ok((relative, blob.stdout))
}

fn parse_arg_file(content: &[u8]) -> Result<BTreeMap<String, String>> {
    let content = std::str::from_utf8(content).context("build arg file must be UTF-8")?;
    let mut args = BTreeMap::new();
    for (line_number, line) in content.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let arg = crate::parse_build_arg(line)
            .map_err(|_| anyhow::anyhow!("invalid build arg at line {}", line_number + 1))?;
        let (name, value) = arg.split_once('=').expect("validated NAME=VALUE");
        ensure!(
            args.insert(name.to_owned(), value.to_owned()).is_none(),
            "duplicate build arg at line {}",
            line_number + 1
        );
    }
    ensure!(!args.is_empty(), "build arg file is empty");
    Ok(args)
}

fn arg_hashes(args: &BTreeMap<String, String>) -> BTreeMap<String, String> {
    args.iter()
        .map(|(name, value)| {
            (
                name.clone(),
                format!("{:x}", Sha256::digest(value.as_bytes())),
            )
        })
        .collect()
}

fn verified_build_metadata(dir: &Path, metadata: &Path) -> Result<Value> {
    let success: Value = read_json(&dir.join("build-succeeded.json"))
        .context("build metadata exists without a recorded successful Buildx exit; preserve state for review")?;
    ensure!(
        success["metadata_sha256"].as_str() == Some(&hash_file(metadata)?),
        "build metadata changed after successful Buildx exit"
    );
    ensure!(
        success["source_tar_sha256"].as_str() == Some(&hash_file(&dir.join("source.tar"))?),
        "build source archive changed after successful Buildx exit"
    );
    read_json(metadata)
}

fn scan_plan(canonical: &str, ignore_unfixed: bool, os_only: bool) -> ProcessPlan {
    let mut plan = ProcessPlan::new("trivy")
        .arg("image")
        .arg("--image-src")
        .arg("docker")
        .arg("--scanners")
        .arg("vuln")
        .arg("--severity")
        .arg("HIGH,CRITICAL")
        .arg("--exit-code")
        .arg("1")
        .arg("--no-progress")
        .arg("--format")
        .arg("json");
    if ignore_unfixed {
        plan = plan.arg("--ignore-unfixed");
    }
    if os_only {
        plan = plan.arg("--pkg-types").arg("os");
    }
    plan.arg(canonical)
}

pub(crate) fn validate_registry(value: &str) -> Result<()> {
    let host = value.split('/').next().unwrap_or_default();
    let hostname = if let Some((name, port)) = host.split_once(':') {
        ensure!(
            port.parse::<u16>().is_ok_and(|port| port > 0),
            "invalid registry port"
        );
        name
    } else {
        host
    };
    ensure!(
        hostname.split('.').all(|part| !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && part.as_bytes()[0].is_ascii_alphanumeric()
            && part.as_bytes()[part.len() - 1].is_ascii_alphanumeric()),
        "invalid registry hostname"
    );
    ensure!(
        !value.is_empty()
            && !value.ends_with('/')
            && !value.contains("//")
            && value
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-:/_".contains(&b))
            && (host.contains('.') || host.contains(':') || host == "localhost")
            && value
                .split('/')
                .skip(1)
                .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains(':')),
        "registry must be a host[:port][/namespace], without scheme, credentials, tag or digest"
    );
    Ok(())
}

fn source_path(path: &Path) -> Result<String> {
    if path.as_os_str().is_empty() {
        return Ok(".".into());
    }
    Ok(path
        .to_str()
        .context("source paths must be UTF-8")?
        .replace('\\', "/"))
}

fn validate_digest(value: &str) -> Result<()> {
    ensure!(
        value.starts_with("sha256:")
            && value.len() == 71
            && value[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid OCI SHA-256 digest"
    );
    Ok(())
}

fn metadata_digest(value: &Value) -> Result<&str> {
    let digest = value["containerimage.digest"]
        .as_str()
        .context("Buildx metadata has no image digest")?;
    validate_digest(digest)?;
    Ok(digest)
}

fn lookup(reference: &str) -> Result<Option<String>> {
    let output = ProcessPlan::new("docker")
        .arg("buildx")
        .arg("imagetools")
        .arg("inspect")
        .arg(reference)
        .arg("--format")
        .arg("{{json .Manifest}}")
        .capture()?;
    if output.status.success() {
        let value: Value = serde_json::from_slice(&output.stdout)?;
        let digest = value["digest"]
            .as_str()
            .context("registry response has no digest")?;
        validate_digest(digest)?;
        return Ok(Some(digest.to_owned()));
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if manifest_missing(&error, reference) {
        return Ok(None);
    }
    bail!(
        "registry lookup failed for {reference} ({}): {}; not treating it as an absent tag",
        output.status,
        registry_lookup_diagnostic(&error)
    )
}

// Docker stderr can contain registry URLs and authentication material. Emit only fixed hints.
fn registry_lookup_diagnostic(error: &str) -> &'static str {
    let lower = error.to_ascii_lowercase();
    if lower.contains("403 forbidden") || lower.contains("403forbidden") {
        "HTTP 403 Forbidden; check registry permissions and authentication"
    } else if lower.contains("401 unauthorized") || lower.contains("401unauthorized") {
        "HTTP 401 Unauthorized; check registry authentication"
    } else if lower.contains("x509") || lower.contains("certificate") || lower.contains("tls") {
        "TLS or certificate failure; check registry trust"
    } else if lower.contains("timeout") || lower.contains("timed out") {
        "registry connection timed out"
    } else if lower.contains("connection") {
        "registry connection failed"
    } else {
        "check registry authentication, TLS and connectivity"
    }
}

fn manifest_missing(error: &str, reference: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    if [
        "unauthorized",
        "forbidden",
        "denied",
        "timeout",
        "timed out",
        "connection",
        "tls",
        "certificate",
    ]
    .iter()
    .any(|word| lower.contains(word))
    {
        return false;
    }
    lower.contains("manifest unknown")
        || lower.contains("no such manifest")
        || error
            .lines()
            .any(|line| line.trim() == format!("ERROR: {reference}: not found"))
}

fn inspect_json(reference: &str, format: Option<&str>) -> Result<Value> {
    let plan = ProcessPlan::new("docker")
        .arg("buildx")
        .arg("imagetools")
        .arg("inspect")
        .arg(reference);
    let plan = match format {
        Some(format) => plan.arg("--format").arg(format),
        None => plan.arg("--raw"),
    };
    serde_json::from_slice(&plan.output()?).context("invalid registry attestation/index JSON")
}

fn platform_digest(index: &Value) -> Result<&str> {
    let entries = index["manifests"]
        .as_array()
        .context("expected attested OCI index")?;
    let matches: Vec<_> = entries
        .iter()
        .filter(|m| {
            m.pointer("/platform/os").and_then(Value::as_str) == Some("linux")
                && m.pointer("/platform/architecture").and_then(Value::as_str) == Some("amd64")
        })
        .collect();
    ensure!(
        matches.len() == 1,
        "expected exactly one linux/amd64 platform manifest"
    );
    let digest = matches[0]["digest"]
        .as_str()
        .context("platform has no digest")?;
    validate_digest(digest)?;
    Ok(digest)
}

fn contains_key(value: &Value, key: &str) -> bool {
    match value {
        Value::Object(map) => {
            map.get(key)
                .and_then(Value::as_str)
                .is_some_and(|s| !s.is_empty())
                || map.values().any(|v| contains_key(v, key))
        }
        Value::Array(items) => items.iter().any(|v| contains_key(v, key)),
        _ => false,
    }
}

fn validate_scan(report: &Value, canonical: &str) -> Result<()> {
    ensure!(
        report["ArtifactName"] == canonical,
        "scan identifies another artifact"
    );
    let targets = report["Results"]
        .as_array()
        .context("scan has no results")?;
    ensure!(
        !targets.is_empty(),
        "scan report is empty; use a scannable fixture"
    );
    for target in targets {
        ensure!(target["Target"].is_string(), "scan result has no target");
        if let Some(items) = target.get("Vulnerabilities").filter(|v| !v.is_null()) {
            for item in items.as_array().context("invalid vulnerability list")? {
                let severity = item["Severity"]
                    .as_str()
                    .context("vulnerability has no severity")?;
                ensure!(
                    !["HIGH", "CRITICAL", "UNKNOWN"].contains(&severity),
                    "scan contains blocked or unknown-severity findings"
                );
            }
        }
    }
    Ok(())
}

fn state_directory(root: &Path, git_root: &Path, target: &str) -> Result<PathBuf> {
    let root = fs::canonicalize(root)
        .context("create a durable evidence directory outside the Git checkout first")?;
    ensure!(root.is_dir(), "evidence root must be a directory");
    ensure!(
        !root.starts_with(git_root),
        "evidence directory must be outside the Git checkout"
    );
    let dir = root.join(format!("{:x}", Sha256::digest(target.as_bytes())));
    regular_or_absent(&dir)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    if !dir.exists() {
        builder.create(&dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            fs::metadata(&dir)?.permissions().mode() & 0o077 == 0,
            "publication state directory must be private (0700)"
        );
    }
    Ok(dir)
}

fn regular_or_absent(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            !meta.file_type().is_symlink(),
            "refusing symlink in publication state: {}",
            path.display()
        );
    }
    Ok(())
}

fn private_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    {
        let _ = options;
    }
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    regular_or_absent(path)?;
    let pending = path.with_extension("pending");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_options(&mut options);
    let mut file = options
        .open(&pending)
        .context("pending evidence exists; preserve interrupted state for reviewed recovery")?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::rename(&pending, path)?;
    #[cfg(unix)]
    {
        File::open(path.parent().context("missing evidence parent")?)?.sync_all()?;
    }
    Ok(())
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    write_bytes(path, &serde_json::to_vec_pretty(value)?)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T> {
    regular_or_absent(path)?;
    serde_json::from_slice(&fs::read(path)?)
        .with_context(|| format!("invalid evidence: {}", path.display()))
}

fn hash_file(path: &Path) -> Result<String> {
    regular_or_absent(path)?;
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn verify_seal(dir: &Path) -> Result<()> {
    let hashes: BTreeMap<String, String> = read_json(&dir.join("checksums.json"))?;
    ensure!(
        hashes.len() == SEALED_FILES.len(),
        "evidence seal has missing or extra files"
    );
    for name in SEALED_FILES {
        ensure!(
            hashes.get(*name) == Some(&hash_file(&dir.join(name))?),
            "sealed evidence changed: {name}"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    fn git(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    #[test]
    fn arg_file_is_strict_and_does_not_echo_values_in_errors() {
        let args = parse_arg_file(
            b"# Public build inputs\nVITE_APP_ENV=development\n\nVITE_API_URL=https://example.test/?a=b\n",
        )
        .unwrap();
        assert_eq!(args["VITE_APP_ENV"], "development");
        assert_eq!(args["VITE_API_URL"], "https://example.test/?a=b");
        for invalid in [
            "VITE_APP_ENV=x\nVITE_APP_ENV=y",
            "API_TOKEN=hunter2",
            "=secret-value",
            "VITE_APP_ENV=x\n VITE_API_URL=y",
            "# comment only",
        ] {
            let error = parse_arg_file(invalid.as_bytes()).unwrap_err().to_string();
            assert!(!error.contains("hunter2") && !error.contains("secret-value"));
        }
    }

    #[test]
    fn arg_file_must_be_committed_inside_context() {
        let root = std::env::temp_dir().join(format!(
            "udt publish args {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("app/ci")).unwrap();
        fs::write(root.join("app/ci/build.env"), "VITE_APP_ENV=committed\n").unwrap();
        fs::write(root.join("outside.env"), "VITE_APP_ENV=outside\n").unwrap();
        git(&root, &["init", "-q"]);
        git(
            &root,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "add",
                ".",
            ],
        );
        git(
            &root,
            &[
                "-c",
                "user.name=Test",
                "-c",
                "user.email=test@example.invalid",
                "commit",
                "-qm",
                "fixture",
            ],
        );
        let snapshot = source::Snapshot {
            revision: git(&root, &["rev-parse", "HEAD"]),
            tree: String::new(),
            config_path: None,
            config_sha256: None,
            dockerfile: PathBuf::new(),
            git_root: fs::canonicalize(&root).unwrap(),
            context: PathBuf::from("app"),
        };
        let path = root.join("app/ci/build.env");
        let (relative, bytes) = committed_arg_file(&snapshot, &path).unwrap();
        assert_eq!(relative, "app/ci/build.env");
        assert_eq!(bytes, b"VITE_APP_ENV=committed\n");
        fs::write(&path, "VITE_APP_ENV=worktree\n").unwrap();
        assert_eq!(committed_arg_file(&snapshot, &path).unwrap().1, bytes);
        assert!(committed_arg_file(&snapshot, &root.join("outside.env")).is_err());
        fs::write(root.join("app/ci/untracked.env"), "X=y\n").unwrap();
        assert!(committed_arg_file(&snapshot, &root.join("app/ci/untracked.env")).is_err());
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = fs::canonicalize(root).unwrap();
        assert_eq!(root.parent(), Some(temp.as_path()));
        assert!(
            root.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("udt publish args ")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn hashed_inputs_change_on_retry_without_storing_values() {
        let first = parse_arg_file(b"VITE_APP_ENV=development\n").unwrap();
        let second = parse_arg_file(b"VITE_APP_ENV=production\n").unwrap();
        let hashes = arg_hashes(&first);
        assert_ne!(hashes, arg_hashes(&second));
        let encoded = serde_json::to_string(&hashes).unwrap();
        assert!(encoded.contains("VITE_APP_ENV"));
        assert!(!encoded.contains("development"));
    }

    #[test]
    fn build_metadata_requires_recorded_success_on_retry() {
        let root = std::env::temp_dir().join(format!(
            "udt build success {} {}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        let archive = root.join("source.tar");
        let metadata = root.join("build-metadata.json");
        fs::write(&archive, b"source").unwrap();
        fs::write(&metadata, b"{}").unwrap();
        assert!(verified_build_metadata(&root, &metadata).is_err());
        write_json(
            &root.join("build-succeeded.json"),
            &json!({
                "metadata_sha256": hash_file(&metadata).unwrap(),
                "source_tar_sha256": hash_file(&archive).unwrap()
            }),
        )
        .unwrap();
        assert!(verified_build_metadata(&root, &metadata).is_ok());
        fs::write(&metadata, b"{\"changed\":true}").unwrap();
        assert!(verified_build_metadata(&root, &metadata).is_err());
        let temp = fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = fs::canonicalize(root).unwrap();
        assert_eq!(root.parent(), Some(temp.as_path()));
        assert!(
            root.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("udt build success ")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn publish_scan_policy_is_explicit() {
        let strict = scan_plan("repo@sha256:demo", false, false);
        assert!(!strict.args.contains(&"--ignore-unfixed".into()));
        assert!(!strict.args.contains(&"--pkg-types".into()));
        let narrowed = scan_plan("repo@sha256:demo", true, true);
        assert!(narrowed.args.contains(&"--ignore-unfixed".into()));
        assert!(
            narrowed
                .args
                .windows(2)
                .any(|pair| pair == ["--pkg-types", "os"])
        );
    }
    #[test]
    fn registry_inputs_do_not_accept_credentials_or_options() {
        for good in [
            "localhost:5000",
            "registry.example.com/team",
            "registry.example.test:5000",
        ] {
            assert!(validate_registry(good).is_ok());
        }
        for bad in [
            "https://host/path",
            "user:secret@host",
            "host/path:tag",
            "--host=x",
            "host/../x",
            "host\n",
        ] {
            assert!(validate_registry(bad).is_err());
        }
    }

    #[test]
    fn registry_lookup_errors_are_bounded_and_missing_tags_stay_distinct() {
        let reference = "localhost:5000/demo/api:abc";
        assert!(manifest_missing(
            &format!("ERROR: {reference}: not found"),
            reference
        ));
        assert!(manifest_missing("manifest unknown", reference));
        for (raw, expected) in [
            (
                "ERROR unexpected status from HEAD https://user:secret@example.test/?token=hidden: 403 Forbidden",
                "HTTP 403 Forbidden; check registry permissions and authentication",
            ),
            (
                "unauthorized: manifest unknown; 401 Unauthorized",
                "HTTP 401 Unauthorized; check registry authentication",
            ),
            (
                "x509: certificate signed by unknown authority",
                "TLS or certificate failure; check registry trust",
            ),
        ] {
            assert!(!manifest_missing(raw, reference));
            let hint = registry_lookup_diagnostic(raw);
            assert_eq!(hint, expected);
            assert!(
                !hint.contains("secret") && !hint.contains("token") && !hint.contains("https://")
            );
        }
    }
    #[test]
    fn only_explicit_manifest_absence_is_retryable() {
        assert!(manifest_missing(
            "ERROR: localhost:5000/demo:abc: not found",
            "localhost:5000/demo:abc"
        ));
        assert!(manifest_missing("manifest unknown", "x"));
        for error in [
            "unauthorized: manifest unknown",
            "connection refused",
            "TLS error",
            "404 proxy page",
            "credentials not found",
            "context deadline exceeded",
        ] {
            assert!(!manifest_missing(error, "x"));
        }
    }
    #[test]
    fn scan_must_identify_the_artifact_and_have_no_blocked_findings() {
        let ok = json!({"ArtifactName":"r@sha256:x","Results":[{"Target":"alpine"}]});
        assert!(validate_scan(&ok, "r@sha256:x").is_ok());
        assert!(validate_scan(&ok, "other").is_err());
        assert!(validate_scan(&json!({"ArtifactName":"r", "Results":[]}), "r").is_err());
        assert!(validate_scan(&json!({"ArtifactName":"r", "Results":[{"Target":"os", "Vulnerabilities":[{"Severity":"HIGH"}]}]}), "r").is_err());
    }
}
