//! One-service, digest-pinned Docker Compose delivery. Runtime inputs are trusted
//! operator files; publication evidence is trusted only after its out-of-band hash.

use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Debug, Args)]
pub struct TargetOptions {
    #[arg(long)]
    pub compose_file: PathBuf,
    #[arg(long)]
    pub env_file: Option<PathBuf>,
    #[arg(long)]
    pub project: String,
    #[arg(long)]
    pub service: String,
    #[arg(long)]
    pub environment: String,
    /// An explicit Docker context; the ambient/default context is never used.
    #[arg(long)]
    pub context: String,
    #[arg(long)]
    pub state_dir: PathBuf,
    #[arg(long, default_value = "IMAGE_REF")]
    pub image_env: String,
    #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub wait_timeout: u64,
}

#[derive(Debug, Args)]
pub struct DeployOptions {
    #[command(flatten)]
    pub target: TargetOptions,
    #[arg(long)]
    pub evidence: PathBuf,
    #[arg(long)]
    pub evidence_sha256: String,
    #[arg(long)]
    pub execute: bool,
}

#[derive(Debug, Args)]
pub struct RollbackOptions {
    #[command(flatten)]
    pub target: TargetOptions,
    #[arg(long)]
    pub execute: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Release {
    image: String,
    image_id: String,
    source_sha: String,
    component: String,
    evidence_sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct Identity {
    daemon_id: String,
    environment: String,
    project: String,
    service: String,
    context: String,
    compose_file: String,
    env_file: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    schema: u32,
    target: Identity,
    contract_sha256: String,
    current: Option<Release>,
    previous: Option<Release>,
    pending: Option<Release>,
}

struct Target<'a> {
    options: &'a TargetOptions,
    identity: Identity,
    daemon_os: String,
    daemon_arch: String,
    local_bind_endpoint: bool,
}

pub fn deploy(options: &DeployOptions) -> Result<()> {
    let started = Instant::now();
    let (mut release, platform) = read_evidence(&options.evidence, &options.evidence_sha256)?;
    let target = Target::new(&options.target)?;
    let contract = target.contract(&release.image)?;
    let state_path = options.target.state_dir.join("state.json");
    if !options.execute {
        let state = read_state(&state_path)?;
        check_state(state.as_ref(), &target.identity, &contract)?;
        ensure!(
            state.as_ref().is_none_or(|s| s.pending.is_none()),
            "interrupted operation; run rollback --execute before deploying"
        );
        report(
            "plan",
            &target,
            Some(&release),
            started,
            "not-started",
            "not-needed",
        );
        return Ok(());
    }

    let _host_lock = host_lock(&target)?;
    let _lock = lock_state(&options.target.state_dir)?;
    let mut state = read_state(&state_path)?.unwrap_or(State {
        schema: 1,
        target: target.identity.clone(),
        contract_sha256: contract.clone(),
        current: None,
        previous: None,
        pending: None,
    });
    check_state(Some(&state), &target.identity, &contract)?;
    ensure!(
        state.pending.is_none(),
        "interrupted operation; run rollback --execute before deploying"
    );
    let live = target.live(&release.image)?;
    check_live(&state, live.as_ref())?;
    if state.current.as_ref().is_some_and(|current| {
        current.image == release.image
            && current.source_sha == release.source_sha
            && current.component == release.component
            && current.evidence_sha256 == release.evidence_sha256
    }) && live.as_ref().is_some_and(healthy)
    {
        report(
            "already-current",
            &target,
            Some(&release),
            started,
            "healthy",
            "not-needed",
        );
        return Ok(());
    }
    target.pull(&release.image)?;
    release.image_id = target.verified_image(&release, platform.as_deref())?;
    if let Some(current) = &state.current {
        // An unchanged digest may have been stopped. Preserve the prior rollback slot.
        if current.image == release.image {
            ensure!(
                current == &release,
                "current release metadata changed for the same digest"
            );
        }
    }
    target.check_healthcheck(&release.image)?;
    state.pending = Some(release.clone());
    persist(&state_path, &state)?;
    let outcome = (|| {
        ensure!(
            target.contract(&release.image)? == contract,
            "runtime contract drift before service update"
        );
        target.up(&release.image)?;
        target.ready(&release)?;
        ensure!(
            target.contract(&release.image)? == contract,
            "runtime contract drift before state commit"
        );
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            if state.current.as_ref() != Some(&release) {
                state.previous = state.current.take();
                state.current = Some(release.clone());
            }
            state.pending = None;
            persist(&state_path, &state)?;
            report(
                "deployed",
                &target,
                Some(&release),
                started,
                "healthy",
                "not-needed",
            );
            Ok(())
        }
        Err(error) => {
            let recovery = if let Some(current) = &state.current {
                restore(&target, current, &contract)
            } else {
                target.cleanup_first(&release.image)
            };
            match recovery {
                Ok(()) => {
                    state.pending = None;
                    persist(&state_path, &state)?;
                    report(
                        "failed",
                        &target,
                        Some(&release),
                        started,
                        "failed",
                        if state.current.is_some() {
                            "restored-current"
                        } else {
                            "stopped-first-deployment"
                        },
                    );
                    bail!(
                        "deployment failed ({error}); prior state restored; no new release committed"
                    )
                }
                Err(restore_error) => {
                    report(
                        "failed",
                        &target,
                        Some(&release),
                        started,
                        "failed",
                        "recovery-failed-pending-preserved",
                    );
                    bail!(
                        "deployment failed ({error}); recovery failed ({restore_error}); pending state preserved; run rollback --execute"
                    )
                }
            }
        }
    }
}

pub fn rollback(options: &RollbackOptions) -> Result<()> {
    let started = Instant::now();
    let target = Target::new(&options.target)?;
    let state_path = options.target.state_dir.join("state.json");
    if !options.execute {
        let state = read_state(&state_path)?.context("no managed delivery state to roll back")?;
        ensure!(
            state.schema == 1 && state.target == target.identity,
            "delivery state belongs to another target"
        );
        let selected = if state.pending.is_some() {
            state.current.as_ref().or(state.pending.as_ref())
        } else {
            state.previous.as_ref()
        };
        let selected = selected.context("no previous or pending verified release to roll back")?;
        ensure!(
            target.contract(&selected.image)? == state.contract_sha256,
            "runtime contract drift; restore reviewed Compose inputs before rollback"
        );
        report(
            "plan",
            &target,
            Some(selected),
            started,
            "not-started",
            "not-started",
        );
        return Ok(());
    }
    let _host_lock = host_lock(&target)?;
    let _lock = lock_state(&options.target.state_dir)?;
    let mut state = read_state(&state_path)?.context("no managed delivery state to roll back")?;
    ensure!(
        state.schema == 1 && state.target == target.identity,
        "delivery state belongs to another target"
    );
    let inspection_image = state
        .pending
        .as_ref()
        .or(state.current.as_ref())
        .or(state.previous.as_ref())
        .map(|r| r.image.as_str())
        .context("delivery state has no release to inspect")?;
    if state.pending.is_some() {
        let containers = target.service_containers(inspection_image)?;
        let candidate_ids = check_pending_containers(&state, &containers)?;
        if let Some(current) = &state.current {
            ensure!(
                target.contract(&current.image)? == state.contract_sha256,
                "runtime contract drift; restore reviewed Compose inputs before rollback"
            );
            target.ensure_release_available(current)?;
            for id in candidate_ids {
                target.remove_verified_candidate(&id)?;
            }
            restore(&target, current, &state.contract_sha256)?;
        } else {
            // Failed/interrupted first adoption: stop only this Compose service.
            let pending = state.pending.as_ref().expect("checked pending");
            ensure!(
                target.contract(&pending.image)? == state.contract_sha256,
                "runtime contract drift; restore reviewed Compose inputs before rollback"
            );
            target.cleanup_first(&pending.image)?;
        }
        let recovered = state.current.clone();
        state.pending = None;
        persist(&state_path, &state)?;
        report(
            "recovered",
            &target,
            recovered.as_ref(),
            started,
            "healthy-or-stopped",
            "pending-cleared",
        );
        return Ok(());
    }
    let live = target.live(inspection_image)?;
    check_live(&state, live.as_ref())?;
    let previous = state
        .previous
        .clone()
        .context("no previous verified release to roll back to")?;
    ensure!(
        target.contract(&previous.image)? == state.contract_sha256,
        "runtime contract drift; restore reviewed Compose inputs before rollback"
    );
    state.pending = Some(previous.clone());
    target.ensure_release_available(&previous)?;
    target.check_healthcheck(&previous.image)?;
    persist(&state_path, &state)?;
    let outcome = (|| {
        ensure!(
            target.contract(&previous.image)? == state.contract_sha256,
            "runtime contract drift before rollback update"
        );
        target.up(&previous.image)?;
        target.ready(&previous)?;
        ensure!(
            target.contract(&previous.image)? == state.contract_sha256,
            "runtime contract drift before rollback commit"
        );
        Ok(())
    })();
    match outcome {
        Ok(()) => {
            state.previous = state.current.take();
            state.current = Some(previous.clone());
            state.pending = None;
            persist(&state_path, &state)?;
            report(
                "rolled-back",
                &target,
                Some(&previous),
                started,
                "healthy",
                "previous-restored",
            );
            Ok(())
        }
        Err(error) => {
            let recovery = state
                .current
                .as_ref()
                .context("missing current release")
                .and_then(|current| restore(&target, current, &state.contract_sha256));
            match recovery {
                Ok(()) => {
                    state.pending = None;
                    persist(&state_path, &state)?;
                    report(
                        "failed",
                        &target,
                        state.current.as_ref(),
                        started,
                        "failed",
                        "restored-current",
                    );
                    bail!("rollback failed ({error}); current release restored")
                }
                Err(restore_error) => {
                    report(
                        "failed",
                        &target,
                        state.current.as_ref(),
                        started,
                        "failed",
                        "recovery-failed-pending-preserved",
                    );
                    bail!(
                        "rollback failed ({error}); recovery failed ({restore_error}); pending state preserved"
                    )
                }
            }
        }
    }
}

fn restore(target: &Target<'_>, release: &Release, contract: &str) -> Result<()> {
    ensure!(
        target.contract(&release.image)? == contract,
        "runtime contract drift; restore reviewed Compose inputs before rollback"
    );
    target.ensure_release_available(release)?;
    target.check_healthcheck(&release.image)?;
    ensure!(
        target.contract(&release.image)? == contract,
        "runtime contract drift before recovery update"
    );
    target.up(&release.image)?;
    target.ready(release)?;
    ensure!(
        target.contract(&release.image)? == contract,
        "runtime contract drift before recovery commit"
    );
    Ok(())
}

fn read_evidence(path: &Path, supplied_hash: &str) -> Result<(Release, Option<String>)> {
    ensure!(
        is_hex(supplied_hash, 64),
        "evidence SHA-256 must be 64 lowercase hex characters"
    );
    let bytes = fs::read(path).context("cannot read publication evidence")?;
    ensure!(
        sha256(&bytes) == supplied_hash,
        "publication evidence SHA-256 mismatch"
    );
    let evidence: Value =
        serde_json::from_slice(&bytes).context("invalid publication evidence JSON")?;
    ensure!(
        evidence["schema"] == 2,
        "unsupported publication evidence schema"
    );
    let reference = field(&evidence, "canonical_ref")?;
    let digest = field(&evidence, "image_digest")?;
    ensure!(valid_digest(digest), "invalid publication image digest");
    let (repository, suffix) = reference
        .rsplit_once('@')
        .context("canonical image reference must contain @digest")?;
    ensure!(
        !repository.is_empty()
            && !repository.contains('@')
            && !repository.contains("//")
            && repository
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || "._:/-".contains(c)),
        "invalid canonical image repository"
    );
    ensure!(
        suffix == digest && reference.ends_with(&format!("@{digest}")),
        "canonical reference and image digest differ"
    );
    if let Some(published_repository) = evidence
        .pointer("/inputs/repository")
        .and_then(Value::as_str)
    {
        ensure!(
            published_repository == repository,
            "publication repository differs from canonical reference"
        );
    }
    ensure!(
        evidence.pointer("/scan/result").and_then(Value::as_str) == Some("passed"),
        "publication scan did not pass"
    );
    let sha = evidence
        .pointer("/inputs/source_sha")
        .and_then(Value::as_str)
        .context("missing source SHA")?;
    ensure!(is_hex(sha, 40), "invalid source SHA");
    let component = evidence
        .pointer("/inputs/component")
        .and_then(Value::as_str)
        .context("missing source component")?;
    ensure!(
        matches!(component, "frontend" | "backend"),
        "unsupported source component"
    );
    let platform = evidence
        .pointer("/inputs/platform")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if let Some(value) = &platform {
        ensure!(value.split('/').count() == 2, "invalid evidence platform");
    }
    Ok((
        Release {
            image: reference.to_owned(),
            image_id: String::new(),
            source_sha: sha.to_owned(),
            component: component.to_owned(),
            evidence_sha256: supplied_hash.to_owned(),
        },
        platform,
    ))
}

fn field<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing publication {key}"))
}

fn valid_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| is_hex(hex, 64))
}

fn is_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl<'a> Target<'a> {
    fn new(options: &'a TargetOptions) -> Result<Self> {
        for (name, value) in [
            ("project", &options.project),
            ("service", &options.service),
            ("environment", &options.environment),
            ("context", &options.context),
        ] {
            ensure!(
                !value.trim().is_empty() && !value.contains(['\n', '\r']),
                "invalid {name}"
            );
        }
        ensure!(
            options.wait_timeout > 0 && options.wait_timeout <= 600,
            "wait timeout must be 1..600 seconds"
        );
        ensure!(
            valid_env_name(&options.image_env),
            "invalid image environment variable name"
        );
        let compose =
            fs::canonicalize(&options.compose_file).context("compose file does not exist")?;
        ensure!(
            fs::metadata(&compose)?.is_file(),
            "compose path is not a regular file"
        );
        let env = options
            .env_file
            .as_ref()
            .map(|p| fs::canonicalize(p).context("env file does not exist"))
            .transpose()?;
        if let Some(path) = &env {
            ensure!(
                fs::metadata(path)?.is_file(),
                "env path is not a regular file"
            );
        }
        let mut command = docker(&options.context);
        command.args(["info", "--format", "{{json .}}"]);
        let info = json_output(command, "Docker daemon identity")?;
        let daemon_id = field(&info, "ID")?.to_owned();
        ensure!(!daemon_id.is_empty(), "Docker daemon ID is empty");
        let daemon_os = field(&info, "OSType")?.to_owned();
        let daemon_arch = field(&info, "Architecture")?.to_owned();
        let mut context_command = Command::new("docker");
        context_command.args(["context", "inspect", &options.context]);
        let context_info = json_output(context_command, "Docker context inspection")?;
        let host = context_info
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.pointer("/Endpoints/docker/Host"))
            .and_then(Value::as_str)
            .context("Docker context has no endpoint")?;
        let local_bind_endpoint = host.starts_with("unix://") || host.starts_with("npipe://");
        Ok(Self {
            options,
            identity: Identity {
                daemon_id,
                environment: options.environment.clone(),
                project: options.project.clone(),
                service: options.service.clone(),
                context: options.context.clone(),
                compose_file: compose.to_string_lossy().into_owned(),
                env_file: env.map(|p| p.to_string_lossy().into_owned()),
            },
            daemon_os,
            daemon_arch,
            local_bind_endpoint,
        })
    }

    fn compose(&self) -> Command {
        let mut command = docker(&self.options.context);
        command
            .arg("compose")
            .arg("--file")
            .arg(&self.identity.compose_file);
        if let Some(env) = &self.identity.env_file {
            command.arg("--env-file").arg(env);
        }
        command.arg("--project-name").arg(&self.options.project);
        command
    }

    fn render(&self, image: &str) -> Result<Value> {
        let mut command = self.compose();
        command
            .env(&self.options.image_env, image)
            .args(["config", "--format", "json"]);
        json_output(command, "Compose render")
    }

    fn contract(&self, image: &str) -> Result<String> {
        let mut rendered = self.render(image)?;
        let service = service_mut(&mut rendered, &self.options.service)?;
        ensure!(
            service["image"].as_str() == Some(image),
            "selected service image is not controlled by the reviewed image environment variable"
        );
        let restart = service["restart"].as_str().unwrap_or("");
        ensure!(
            matches!(restart, "always" | "unless-stopped"),
            "selected service requires restart: always or unless-stopped"
        );
        for count in [&service["scale"], &service["deploy"]["replicas"]] {
            ensure!(
                count.is_null() || count.as_u64() == Some(1),
                "selected service must have exactly one replica"
            );
        }
        self.check_mounts(&rendered)?;
        self.check_dependencies(&rendered, image)?;
        let alternate = format!(
            "{}@sha256:{}",
            image.split('@').next().unwrap_or("invalid"),
            "0".repeat(64)
        );
        ensure!(
            alternate != image,
            "cannot derive alternate image for contract check"
        );
        let mut altered = self.render(&alternate)?;
        ensure!(
            service_mut(&mut altered, &self.options.service)?["image"].as_str()
                == Some(alternate.as_str()),
            "image environment variable does not select exactly one service image"
        );
        service_mut(&mut rendered, &self.options.service)?["image"] = json!("<selected-image>");
        service_mut(&mut altered, &self.options.service)?["image"] = json!("<selected-image>");
        ensure!(
            rendered == altered,
            "image environment variable changes fields outside the selected service image"
        );
        Ok(sha256(&serde_json::to_vec(&rendered)?))
    }

    fn check_mounts(&self, config: &Value) -> Result<()> {
        let service = &config["services"][&self.options.service];
        if let Some(mounts) = service.get("volumes") {
            let mounts = mounts
                .as_array()
                .context("Compose volumes must be an array")?;
            for mount in mounts {
                let source = mount["source"].as_str().context(
                    "anonymous mounts are not allowed; pre-provision a named volume or bind path",
                )?;
                match mount["type"].as_str().context("mount type is missing")? {
                    "bind" => {
                        ensure!(
                            self.local_bind_endpoint,
                            "cannot validate bind paths through a remote Docker endpoint; run delivery on the target host"
                        );
                        ensure!(
                            Path::new(source).exists(),
                            "bind mount source is not pre-provisioned"
                        );
                    }
                    "volume" => {
                        let volume_name =
                            config["volumes"][source]["name"].as_str().unwrap_or(source);
                        let mut command = docker(&self.options.context);
                        command.args(["volume", "inspect", volume_name]);
                        checked(command, "named volume preflight")?;
                    }
                    _ => bail!("unsupported mount type; use pre-provisioned bind or named volume"),
                }
            }
        }
        Ok(())
    }

    fn check_dependencies(&self, config: &Value, image: &str) -> Result<()> {
        let dependencies = &config["services"][&self.options.service]["depends_on"];
        if dependencies.is_null() {
            return Ok(());
        }
        let dependencies = dependencies
            .as_object()
            .context("Compose dependencies must be explicit named services")?;
        for (name, requirement) in dependencies {
            let condition = requirement["condition"]
                .as_str()
                .unwrap_or("service_started");
            let container = self
                .container_for(name, image)?
                .context("required dependency is not pre-started")?;
            let state = &container["State"];
            let satisfied = match condition {
                "service_started" => state["Status"] == "running",
                "service_healthy" => healthy(&container),
                "service_completed_successfully" => {
                    state["Status"] == "exited" && state["ExitCode"] == 0
                }
                _ => bail!("unsupported Compose dependency condition"),
            };
            ensure!(
                satisfied,
                "required dependency is not in its declared state"
            );
        }
        Ok(())
    }

    fn pull(&self, image: &str) -> Result<()> {
        let mut command = docker(&self.options.context);
        command.args(["pull", image]);
        checked(command, "image pull")?;
        Ok(())
    }

    fn image(&self, image: &str) -> Result<Value> {
        self.image_optional(image)?
            .context("approved image is absent locally")
    }

    fn image_optional(&self, image: &str) -> Result<Option<Value>> {
        let mut command = docker(&self.options.context);
        command.args(["image", "inspect", image]);
        let output = command
            .output()
            .context("image inspection: cannot start Docker")?;
        if !output.status.success() {
            if missing_image_message(&output.stderr) {
                return Ok(None);
            }
            bail!("image inspection failed ({})", output.status);
        }
        let inspected: Value = serde_json::from_slice(&output.stdout)
            .context("image inspection: invalid Docker JSON")?;
        Ok(Some(
            inspected
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .context("image inspection returned no image")?,
        ))
    }

    fn ensure_release_available(&self, release: &Release) -> Result<()> {
        if self.image_optional(&release.image)?.is_none() {
            self.pull(&release.image)?;
        }
        ensure!(
            self.verified_image(release, None)? == release.image_id,
            "cached or pulled image ID differs from verified state"
        );
        Ok(())
    }

    fn verified_image(&self, release: &Release, platform: Option<&str>) -> Result<String> {
        let image = self.image(&release.image)?;
        ensure!(
            image["RepoDigests"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(&release.image))),
            "pulled image lacks the approved repository digest"
        );
        ensure!(
            image
                .pointer("/Config/Labels/org.opencontainers.image.revision")
                .and_then(Value::as_str)
                == Some(&release.source_sha),
            "image revision label differs from publication evidence"
        );
        ensure!(
            image
                .pointer("/Config/Labels/org.opencontainers.image.source-component")
                .and_then(Value::as_str)
                == Some(&release.component),
            "image component label differs from publication evidence"
        );
        let os = field(&image, "Os")?;
        let arch = field(&image, "Architecture")?;
        ensure!(
            os == self.daemon_os && normalized_arch(arch) == normalized_arch(&self.daemon_arch),
            "image OS/architecture differs from Docker daemon"
        );
        if let Some(platform) = platform {
            ensure!(
                format!("{os}/{arch}") == platform,
                "image OS/architecture differs from publication evidence"
            );
        }
        Ok(field(&image, "Id")?.to_owned())
    }

    fn check_healthcheck(&self, image_ref: &str) -> Result<()> {
        let config = self.render(image_ref)?;
        let service = &config["services"][&self.options.service];
        let compose_test = &service["healthcheck"]["test"];
        ensure!(
            service["healthcheck"]["disable"] != true && !health_disabled(compose_test),
            "selected service disables its healthcheck"
        );
        let compose_health = compose_test.is_array() || compose_test.is_string();
        let image = self.image(image_ref)?;
        let image_health = image
            .pointer("/Config/Healthcheck/Test")
            .is_some_and(|v| !v.is_null() && !health_disabled(v));
        ensure!(
            compose_health || image_health,
            "selected service/image has no explicit healthcheck"
        );
        Ok(())
    }

    fn up(&self, image: &str) -> Result<()> {
        let mut command = self.compose();
        command
            .env(&self.options.image_env, image)
            .args([
                "up",
                "--detach",
                "--no-build",
                "--no-deps",
                "--pull",
                "never",
                "--wait",
                "--wait-timeout",
            ])
            .arg(self.options.wait_timeout.to_string())
            .arg(&self.options.service);
        checked(command, "Compose service up")?;
        Ok(())
    }

    fn stop(&self, image: &str) -> Result<()> {
        let mut command = self.compose();
        command
            .env(&self.options.image_env, image)
            .args(["stop", "--timeout", "30"])
            .arg(&self.options.service);
        checked(command, "Compose service stop")?;
        Ok(())
    }

    fn cleanup_first(&self, image: &str) -> Result<()> {
        self.stop(image)?;
        let mut command = self.compose();
        command
            .env(&self.options.image_env, image)
            .args(["rm", "--force"])
            .arg(&self.options.service);
        checked(command, "failed first-deployment container removal")?;
        ensure!(
            self.live(image)?.is_none(),
            "failed first-deployment container remains"
        );
        Ok(())
    }

    fn live(&self, image: &str) -> Result<Option<Value>> {
        self.container_for(&self.options.service, image)
    }

    fn container_for(&self, service: &str, image: &str) -> Result<Option<Value>> {
        let mut containers = self.containers_for(service, image)?;
        ensure!(
            containers.len() <= 1,
            "selected Compose service has multiple containers; one-service delivery requires one replica"
        );
        let container = containers.pop();
        if let Some(container) = &container {
            ensure!(
                container
                    .pointer("/Config/Labels/com.docker.compose.project")
                    .and_then(Value::as_str)
                    == Some(&self.options.project)
                    && container
                        .pointer("/Config/Labels/com.docker.compose.service")
                        .and_then(Value::as_str)
                        == Some(service),
                "service container has wrong Compose project/service labels"
            );
        }
        Ok(container)
    }

    fn service_containers(&self, image: &str) -> Result<Vec<Value>> {
        self.containers_for(&self.options.service, image)
    }

    fn containers_for(&self, service: &str, image: &str) -> Result<Vec<Value>> {
        let mut command = self.compose();
        command
            .env(&self.options.image_env, image)
            .args(["ps", "--all", "--quiet"])
            .arg(service);
        let output = checked(command, "Compose service listing")?;
        let ids: Vec<_> = String::from_utf8(output.stdout)
            .context("non-UTF8 Docker container IDs")?
            .lines()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let mut containers = Vec::with_capacity(ids.len());
        for id in &ids {
            let mut command = docker(&self.options.context);
            command.args(["inspect", id]);
            let inspected = json_output(command, "service container inspection")?;
            let container = inspected
                .as_array()
                .and_then(|a| a.first())
                .cloned()
                .context("container inspection returned no container")?;
            containers.push(container);
        }
        Ok(containers)
    }

    fn remove_verified_candidate(&self, id: &str) -> Result<()> {
        let mut command = docker(&self.options.context);
        command.args(["rm", "--force", id]);
        checked(command, "verified pending container removal")?;
        Ok(())
    }

    fn ready(&self, release: &Release) -> Result<()> {
        let live = self
            .live(&release.image)?
            .context("Compose service has no container after up")?;
        ensure!(
            live["Image"].as_str() == Some(&release.image_id),
            "running service image ID differs from verified image"
        );
        ensure!(
            live.pointer("/Config/Image").and_then(Value::as_str) == Some(&release.image),
            "running service image reference differs from verified digest"
        );
        ensure!(
            healthy(&live),
            "selected service is not running and healthy"
        );
        Ok(())
    }
}

fn service_mut<'a>(config: &'a mut Value, name: &str) -> Result<&'a mut Value> {
    config
        .get_mut("services")
        .and_then(|s| s.get_mut(name))
        .context("selected Compose service is absent")
}

fn valid_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn normalized_arch(value: &str) -> &str {
    match value {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    }
}

fn missing_image_message(stderr: &[u8]) -> bool {
    let message = String::from_utf8_lossy(stderr);
    message.contains("No such image:") || message.contains("No such object:")
}

fn health_disabled(test: &Value) -> bool {
    test == "NONE"
        || test
            .as_array()
            .is_some_and(|items| items.first().and_then(Value::as_str) == Some("NONE"))
}

fn docker(context: &str) -> Command {
    let mut command = Command::new("docker");
    command.args(["--context", context]);
    command
}

fn checked(mut command: Command, stage: &str) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("{stage}: cannot start Docker"))?;
    ensure!(
        output.status.success(),
        "{stage} failed ({})",
        output.status
    );
    Ok(output)
}

fn json_output(command: Command, stage: &str) -> Result<Value> {
    let output = checked(command, stage)?;
    serde_json::from_slice(&output.stdout).with_context(|| format!("{stage}: invalid Docker JSON"))
}

fn healthy(container: &Value) -> bool {
    container.pointer("/State/Status").and_then(Value::as_str) == Some("running")
        && container
            .pointer("/State/Health/Status")
            .and_then(Value::as_str)
            == Some("healthy")
}

fn check_live(state: &State, live: Option<&Value>) -> Result<()> {
    match (state.current.as_ref(), state.pending.as_ref(), live) {
        (None, None, Some(_)) => {
            bail!("untracked existing service container; adopt explicitly outside this tool")
        }
        (None, Some(pending), Some(container)) => ensure!(
            container["Image"].as_str() == Some(&pending.image_id)
                && container.pointer("/Config/Image").and_then(Value::as_str)
                    == Some(&pending.image),
            "live container differs from pending release"
        ),
        (Some(current), pending, Some(container)) => {
            let image = container["Image"].as_str();
            let reference = container.pointer("/Config/Image").and_then(Value::as_str);
            ensure!(
                (image == Some(&current.image_id) && reference == Some(&current.image))
                    || pending
                        .is_some_and(|p| image == Some(&p.image_id) && reference == Some(&p.image)),
                "live container differs from managed current/pending release"
            );
        }
        (Some(_), None, None) => {
            bail!("managed service container is missing; inspect target before changing state")
        }
        (Some(_), Some(_), None) => {}
        (None, None, None) | (None, Some(_), None) => {}
    }
    Ok(())
}

fn check_pending_containers(state: &State, containers: &[Value]) -> Result<Vec<String>> {
    let pending = state
        .pending
        .as_ref()
        .context("no pending release to recover")?;
    ensure!(
        containers.len() <= 2,
        "pending recovery found too many service containers"
    );
    let mut current_count = 0;
    let mut candidate_ids = Vec::new();
    for container in containers {
        ensure!(
            container
                .pointer("/Config/Labels/com.docker.compose.project")
                .and_then(Value::as_str)
                == Some(&state.target.project)
                && container
                    .pointer("/Config/Labels/com.docker.compose.service")
                    .and_then(Value::as_str)
                    == Some(&state.target.service)
                && container
                    .pointer("/Config/Labels/com.docker.compose.container-number")
                    .and_then(Value::as_str)
                    == Some("1"),
            "pending service container has wrong Compose identity or replica number"
        );
        let image_id = container["Image"].as_str();
        let reference = container.pointer("/Config/Image").and_then(Value::as_str);
        if state.current.as_ref().is_some_and(|current| {
            image_id == Some(&current.image_id) && reference == Some(&current.image)
        }) {
            current_count += 1;
        } else if image_id == Some(&pending.image_id) && reference == Some(&pending.image) {
            candidate_ids.push(field(container, "Id")?.to_owned());
        } else {
            bail!("pending service container is not the recorded current or candidate image");
        }
    }
    ensure!(
        current_count <= 1 && candidate_ids.len() <= 1,
        "pending recovery found duplicate current/candidate containers"
    );
    Ok(candidate_ids)
}

fn check_state(state: Option<&State>, target: &Identity, contract: &str) -> Result<()> {
    if let Some(state) = state {
        ensure!(state.schema == 1, "unsupported delivery state schema");
        ensure!(
            &state.target == target,
            "delivery state belongs to another daemon/environment/project/service/context/Compose target"
        );
        ensure!(
            state.contract_sha256 == contract,
            "runtime contract drift; restore reviewed Compose inputs before deploy or rollback"
        );
    }
    Ok(())
}

fn private_dir(path: &Path, create: bool) -> Result<()> {
    if create && !path.exists() {
        #[allow(unused_mut)]
        let mut builder = DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(path)
            .context("cannot create private delivery state directory")?;
    }
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "delivery state path must be a real directory"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "delivery state directory must be private (0700)"
            );
        }
    }
    Ok(())
}

fn regular_private(path: &Path) -> Result<()> {
    if let Ok(meta) = fs::symlink_metadata(path) {
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "delivery state file must be regular, not a symlink"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o077 == 0,
                "delivery state file must be private (0600)"
            );
        }
    }
    Ok(())
}

fn private_open(options: &mut OpenOptions) {
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

fn lock_state(dir: &Path) -> Result<File> {
    private_dir(dir, true)?;
    let path = dir.join("lock");
    regular_private(&path)?;
    let mut options = OpenOptions::new();
    options.create(true).read(true).write(true);
    private_open(&mut options);
    let file = options.open(path)?;
    file.try_lock()
        .context("another delivery operation is active for this target")?;
    Ok(file)
}

fn host_lock(target: &Target<'_>) -> Result<File> {
    ensure!(
        target.local_bind_endpoint,
        "delivery execution requires a local unix/npipe Docker context on the designated publisher host"
    );
    #[cfg(unix)]
    let root = PathBuf::from("/var/lib/devops-tool/delivery-locks");
    #[cfg(windows)]
    let root = PathBuf::from(std::env::var_os("ProgramData").context("ProgramData is unset")?)
        .join("devops-tool")
        .join("delivery-locks");
    host_lock_in(&root, &target.identity)
}

fn host_lock_in(root: &Path, identity: &Identity) -> Result<File> {
    ensure!(
        root.exists(),
        "private host delivery-lock registry must be provisioned before execution"
    );
    private_dir(root, false)?;
    let key = sha256(
        format!(
            "{}\0{}\0{}",
            identity.daemon_id, identity.project, identity.service
        )
        .as_bytes(),
    );
    lock_state(&root.join(key))
}

fn read_state(path: &Path) -> Result<Option<State>> {
    if let Some(parent) = path.parent() {
        private_dir(parent, false)?;
    }
    regular_private(path)?;
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    Ok(Some(
        serde_json::from_slice(&bytes).context("invalid delivery state JSON")?,
    ))
}

fn persist(path: &Path, state: &State) -> Result<()> {
    regular_private(path)?;
    let parent = path.parent().context("state file has no parent")?;
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temporary = parent.join(format!("state.{}.{}.tmp", std::process::id(), nonce));
    regular_private(&temporary)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    private_open(&mut options);
    let mut file = options
        .open(&temporary)
        .context("stale temporary state file; inspect before retry")?;
    file.write_all(&serde_json::to_vec(state)?)?;
    file.sync_all()?;
    fs::rename(&temporary, path)?;
    #[cfg(unix)]
    {
        File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn report(
    result: &str,
    target: &Target<'_>,
    release: Option<&Release>,
    started: Instant,
    readiness: &str,
    rollback: &str,
) {
    println!(
        "{}",
        json!({
            "result": result,
            "context": target.options.context,
            "environment": target.options.environment,
            "project": target.options.project,
            "service": target.options.service,
            "source_sha": release.map(|r| r.source_sha.as_str()),
            "image": release.map(|r| r.image.as_str()),
            "evidence_sha256": release.map(|r| r.evidence_sha256.as_str()),
            "elapsed_ms": started.elapsed().as_millis(),
            "readiness": readiness,
            "rollback": rollback,
        })
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> Vec<u8> {
        let digest = format!("sha256:{}", "a".repeat(64));
        serde_json::to_vec(&json!({"schema":2,"canonical_ref":format!("registry.test/app@{digest}"),"image_digest":digest,"inputs":{"source_sha":"b".repeat(40),"component":"backend","platform":"linux/amd64"},"scan":{"result":"passed"}})).unwrap()
    }

    #[test]
    fn evidence_digest_and_source_are_bound() {
        let bytes = evidence();
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("delivery-evidence-{}-{nonce}", std::process::id()));
        fs::write(&path, &bytes).unwrap();
        let hash = sha256(&bytes);
        assert!(read_evidence(&path, &hash).is_ok());
        assert!(read_evidence(&path, &"0".repeat(64)).is_err());
        let mut changed: Value = serde_json::from_slice(&bytes).unwrap();
        changed["image_digest"] = json!(format!("sha256:{}", "c".repeat(64)));
        let changed = serde_json::to_vec(&changed).unwrap();
        fs::write(&path, &changed).unwrap();
        assert!(read_evidence(&path, &sha256(&changed)).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn target_state_and_adoption_are_strict() {
        let id = Identity {
            daemon_id: "daemon".into(),
            environment: "Development".into(),
            project: "p".into(),
            service: "s".into(),
            context: "remote".into(),
            compose_file: "/srv/compose.yml".into(),
            env_file: None,
        };
        let state = State {
            schema: 1,
            target: id.clone(),
            contract_sha256: "contract".into(),
            current: None,
            previous: None,
            pending: None,
        };
        assert!(check_state(Some(&state), &id, "contract").is_ok());
        assert!(check_state(Some(&state), &id, "changed").is_err());
        assert!(check_live(&state, Some(&json!({"Image":"untracked"}))).is_err());
        assert!(check_live(&state, None).is_ok());
    }

    #[test]
    fn only_not_found_image_inspection_may_trigger_pull() {
        assert!(missing_image_message(
            b"Error response from daemon: No such image: registry.test/app@sha256:abc"
        ));
        assert!(!missing_image_message(
            b"permission denied while inspecting image"
        ));
        assert!(!missing_image_message(
            b"Cannot connect to the Docker daemon"
        ));
    }

    #[test]
    fn host_lock_serializes_context_and_environment_aliases() {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("delivery-lock-test-{}-{nonce}", std::process::id()));
        private_dir(&root, true).unwrap();
        let identity = Identity {
            daemon_id: "daemon".into(),
            environment: "Development".into(),
            project: "project".into(),
            service: "api".into(),
            context: "desktop-linux".into(),
            compose_file: "compose.yml".into(),
            env_file: None,
        };
        let held = host_lock_in(&root, &identity).unwrap();
        let mut alias = identity.clone();
        alias.environment = "other".into();
        alias.context = "default".into();
        assert!(host_lock_in(&root, &alias).is_err());
        drop(held);
        assert!(host_lock_in(&root, &alias).is_ok());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pending_recovery_accepts_only_recorded_replica_one_images() {
        let current = Release {
            image: "repo@sha256:old".into(),
            image_id: "old-id".into(),
            source_sha: "a".repeat(40),
            component: "backend".into(),
            evidence_sha256: "b".repeat(64),
        };
        let pending = Release {
            image: "repo@sha256:new".into(),
            image_id: "new-id".into(),
            source_sha: "c".repeat(40),
            component: "backend".into(),
            evidence_sha256: "d".repeat(64),
        };
        let state = State {
            schema: 1,
            target: Identity {
                daemon_id: "daemon".into(),
                environment: "Development".into(),
                project: "p".into(),
                service: "api".into(),
                context: "local".into(),
                compose_file: "compose.yml".into(),
                env_file: None,
            },
            contract_sha256: "contract".into(),
            current: Some(current),
            previous: None,
            pending: Some(pending),
        };
        let old = json!({"Id":"old-container","Image":"old-id","Config":{"Image":"repo@sha256:old","Labels":{"com.docker.compose.project":"p","com.docker.compose.service":"api","com.docker.compose.container-number":"1"}}});
        let new = json!({"Id":"new-container","Image":"new-id","Config":{"Image":"repo@sha256:new","Labels":{"com.docker.compose.project":"p","com.docker.compose.service":"api","com.docker.compose.container-number":"1"}}});
        assert_eq!(
            check_pending_containers(&state, &[old.clone(), new.clone()]).unwrap(),
            ["new-container"]
        );
        assert!(check_pending_containers(&state, &[new.clone(), new.clone()]).is_err());
        let mut unknown = new.clone();
        unknown["Image"] = json!("unknown-id");
        assert!(check_pending_containers(&state, &[old.clone(), unknown]).is_err());
        let mut other_replica = new;
        other_replica["Config"]["Labels"]["com.docker.compose.container-number"] = json!("2");
        assert!(check_pending_containers(&state, &[old, other_replica]).is_err());
    }
}
