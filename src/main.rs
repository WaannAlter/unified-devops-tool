mod config;
mod database;
mod delivery;
mod kubernetes;
mod onboarding;
mod process;
mod publish;
mod scaffold;
mod source;

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use clap::{Parser, Subcommand};
use config::{Engine, LoadedConfig, Workload};
use process::ProcessPlan;
use serde_json::Value;
use veriv_toolkit::runner;

#[derive(Debug, Parser)]
#[command(
    name = "devops-tool",
    version,
    about = "Container build, verification, publication, and recovery workflows"
)]
struct Cli {
    /// Explicit configuration file; otherwise use devops.toml when present.
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Whole-operation deadline on Linux; interrupted delivery requires rollback/recovery.
    #[arg(long, global = true, default_value_t = 1800, value_parser = clap::value_parser!(u64).range(1..=86400))]
    operation_timeout: u64,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Preview or create Dockerfile/Compose starter files without overwriting anything.
    Scaffold(scaffold::ScaffoldOptions),
    /// Validate configuration or conventional Dockerfile/CLI inputs and local paths.
    Validate {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
    },
    /// Validate configuration and required local tools.
    Doctor,
    /// List configured workloads.
    List,
    /// Plan or execute a local container build from the working tree.
    Build {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
        /// Repeatable non-secret Dockerfile ARG (NAME=VALUE); never use for credentials.
        #[arg(long = "build-arg", value_parser = parse_build_arg)]
        build_args: Vec<String>,
        /// Exact source revision. Defaults to the repository HEAD.
        #[arg(long)]
        commit: Option<String>,
        /// Execute the build. Without this flag, only a safe plan is printed.
        #[arg(long)]
        execute: bool,
    },
    /// Plan or run a Dockerfile test stage without tagging or publishing an image.
    Check {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
        /// Dockerfile stage to run (for example, test).
        #[arg(long, value_parser = parse_target)]
        target: String,
        /// Repeatable non-secret Dockerfile ARG (NAME=VALUE); never use for credentials.
        #[arg(long = "build-arg", value_parser = parse_build_arg)]
        build_args: Vec<String>,
        /// Execute the check. Without this flag, only a safe plan is printed.
        #[arg(long)]
        execute: bool,
    },
    /// Compare a local image's revision and workload labels.
    Verify {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
        #[arg(long)]
        commit: Option<String>,
    },
    /// Plan or execute a HIGH/CRITICAL vulnerability scan with Trivy.
    Scan {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
        #[arg(long)]
        commit: Option<String>,
        /// Match policies that gate only vulnerabilities with an available fix.
        #[arg(long)]
        ignore_unfixed: bool,
        /// Scan operating-system packages only; excludes language dependencies.
        #[arg(long)]
        os_only: bool,
        /// Execute the scan. Without this flag, only a safe plan is printed.
        #[arg(long)]
        execute: bool,
    },
    /// Publish a verified Git snapshot through a scanned, immutable candidate.
    Publish {
        #[arg(long)]
        workload: Option<String>,
        #[command(flatten)]
        options: onboarding::BuildOptions,
        #[arg(long)]
        commit: Option<String>,
        /// Private durable state directory outside the source Git checkout.
        #[arg(long)]
        evidence_dir: PathBuf,
        /// Committed, non-secret NAME=VALUE lines inside the build context.
        #[arg(long)]
        build_arg_file: Option<PathBuf>,
        /// Gate only vulnerabilities with an available fix.
        #[arg(long)]
        ignore_unfixed: bool,
        /// Scan operating-system packages only.
        #[arg(long)]
        os_only: bool,
        /// Reuse completed sealed evidence across toolkit versions after a fresh scan.
        #[arg(long)]
        reuse_sealed: bool,
        /// Without this flag, only validate inputs and print the publication plan.
        #[arg(long)]
        execute: bool,
    },
    /// Deploy a verified image digest to one Compose service with guarded recovery.
    Deploy(delivery::DeployOptions),
    /// Restore the previous healthy image or recover an interrupted deployment.
    Rollback(delivery::RollbackOptions),
    /// Apply, inspect, or roll back Development Kubernetes workloads.
    Kube {
        #[command(subcommand)]
        command: kubernetes::KubeCommands,
    },
    /// Run the project's unified verification profile through veriv-toolkit.
    Quality {
        /// Use a reviewed profile directly, without a project devops.toml.
        #[arg(long)]
        profile: Option<PathBuf>,
        #[arg(long)]
        group: Option<String>,
        #[arg(long)]
        component: Option<String>,
        #[arg(long)]
        suite: Option<String>,
        #[arg(long)]
        report: Option<PathBuf>,
        /// Execute the checks. Without this flag, only a safe plan is printed.
        #[arg(long)]
        execute: bool,
    },
    /// PostgreSQL backup, archive verification, and guarded restore.
    Database {
        #[command(subcommand)]
        command: DatabaseCommands,
    },
}

#[derive(Debug, Subcommand)]
enum DatabaseCommands {
    /// Create a custom-format backup and SHA-256 sidecar.
    Backup {
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        execute: bool,
    },
    /// Verify both the SHA-256 sidecar and PostgreSQL archive structure.
    VerifyBackup {
        #[arg(long)]
        input: PathBuf,
    },
    /// Restore a verified archive, guarded by exact database-name confirmation.
    Restore {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        confirm_database: Option<String>,
        /// Exact host:port/database from the plan; protects same-named databases on other hosts.
        #[arg(long)]
        confirm_target: Option<String>,
        #[arg(long)]
        execute: bool,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(error) = process::supervise(cli.operation_timeout).and_then(|()| run(cli)) {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    let config_path = cli
        .config
        .as_deref()
        .unwrap_or_else(|| Path::new("devops.toml"));
    match &cli.command {
        Commands::Scaffold(options) => {
            if cli.config.is_some() {
                bail!("scaffold uses explicit context; --config is not supported");
            }
            return scaffold::run(options);
        }
        Commands::Kube { command } => {
            if cli.config.is_some() {
                bail!("kube uses explicit context and namespace; --config is not supported");
            }
            return kubernetes::run(command);
        }
        Commands::Deploy(options) => {
            if cli.config.is_some() {
                bail!("deploy uses explicit runtime inputs; --config is not supported");
            }
            return delivery::deploy(options);
        }
        Commands::Rollback(options) => {
            if cli.config.is_some() {
                bail!("rollback uses explicit runtime inputs; --config is not supported");
            }
            return delivery::rollback(options);
        }
        Commands::Validate { workload, options } => {
            return onboarding::validate(cli.config.as_deref(), workload.as_deref(), options);
        }
        Commands::Build {
            workload,
            options,
            build_args,
            commit,
            execute,
        } => {
            let (loaded, name, _) =
                onboarding::load(cli.config.as_deref(), workload.as_deref(), options)?;
            return build(&loaded, &name, commit.as_deref(), build_args, *execute);
        }
        Commands::Check {
            workload,
            options,
            target,
            build_args,
            execute,
        } => {
            let (loaded, name, _) =
                onboarding::load(cli.config.as_deref(), workload.as_deref(), options)?;
            let plan = check_plan(&loaded, loaded.workload(&name)?, target, build_args)?;
            println!("command\t{}", plan.display());
            if *execute {
                plan.run()?;
                println!("result\tcheck-passed");
            } else {
                println!("result\tplan-only (pass --execute to check)");
            }
            return Ok(());
        }
        Commands::Verify {
            workload,
            options,
            commit,
        } => {
            let (loaded, name, _) =
                onboarding::load(cli.config.as_deref(), workload.as_deref(), options)?;
            return verify(&loaded, &name, commit.as_deref());
        }
        Commands::Scan {
            workload,
            options,
            commit,
            ignore_unfixed,
            os_only,
            execute,
        } => {
            let (loaded, name, _) =
                onboarding::load(cli.config.as_deref(), workload.as_deref(), options)?;
            return scan(
                &loaded,
                &name,
                commit.as_deref(),
                *ignore_unfixed,
                *os_only,
                *execute,
            );
        }
        Commands::Publish {
            workload,
            options,
            commit,
            evidence_dir,
            build_arg_file,
            ignore_unfixed,
            os_only,
            reuse_sealed,
            execute,
        } => {
            let (loaded, name, configured) =
                onboarding::load(cli.config.as_deref(), workload.as_deref(), options)?;
            let revision = resolve_commit(&loaded, commit.as_deref())?;
            return publish::publish(
                &loaded,
                configured.as_deref(),
                &name,
                &revision,
                evidence_dir,
                publish::PublishOptions {
                    build_arg_file: build_arg_file.as_deref(),
                    ignore_unfixed: *ignore_unfixed,
                    os_only: *os_only,
                    reuse_sealed: *reuse_sealed,
                },
                *execute,
            );
        }
        Commands::Quality {
            profile: Some(profile),
            group,
            component,
            suite,
            report,
            execute,
        } => {
            if cli.config.is_some() {
                bail!("--profile and --config cannot be used together");
            }
            let profile = std::fs::canonicalize(profile)
                .with_context(|| format!("cannot open profile {}", profile.display()))?;
            let root = std::env::current_dir()?;
            return quality(
                &profile,
                &root,
                group.as_deref(),
                component.as_deref(),
                suite.as_deref(),
                report.as_deref(),
                *execute,
            );
        }
        _ => {}
    }
    if matches!(cli.command, Commands::Doctor)
        && cli.config.is_none()
        && !config_path.try_exists()?
    {
        return doctor_standalone();
    }
    if let Commands::Database { command } = cli.command {
        let target = if cli.config.is_some() || config_path.try_exists()? {
            database::Target::from_config(LoadedConfig::load(config_path)?)
        } else {
            database::Target::standalone()?
        };
        return match command {
            DatabaseCommands::Backup { output, execute } => {
                database::backup(&target, &output, execute)
            }
            DatabaseCommands::VerifyBackup { input } => database::verify_backup(&target, &input),
            DatabaseCommands::Restore {
                input,
                confirm_database,
                confirm_target,
                execute,
            } => database::restore(
                &target,
                &input,
                confirm_database.as_deref(),
                confirm_target.as_deref(),
                execute,
            ),
        };
    }
    let loaded = LoadedConfig::load(config_path)?;
    match cli.command {
        Commands::Doctor => doctor(&loaded),
        Commands::List => {
            for workload in &loaded.config.workloads {
                println!(
                    "{}\t{}\t{}\t{}",
                    workload.name,
                    workload.kind.as_str(),
                    workload.engine.program(),
                    workload.platforms[0]
                );
            }
            Ok(())
        }
        Commands::Scaffold(_)
        | Commands::Validate { .. }
        | Commands::Build { .. }
        | Commands::Check { .. }
        | Commands::Verify { .. }
        | Commands::Scan { .. }
        | Commands::Publish { .. }
        | Commands::Deploy(_)
        | Commands::Rollback(_)
        | Commands::Kube { .. } => {
            unreachable!("workload commands are dispatched before required configuration loading")
        }
        Commands::Quality {
            profile: None,
            group,
            component,
            suite,
            report,
            execute,
        } => {
            let verification = loaded
                .config
                .verification
                .as_ref()
                .context("[verification] is not configured")?;
            let profile = loaded.resolve_file(&verification.profile)?;
            quality(
                &profile,
                &loaded.root,
                group.as_deref(),
                component.as_deref(),
                suite.as_deref(),
                report.as_deref(),
                execute,
            )
        }
        Commands::Quality {
            profile: Some(_), ..
        } => unreachable!("explicit profile is dispatched before configuration loading"),
        Commands::Database { .. } => {
            unreachable!("database is dispatched before application configuration")
        }
    }
}

fn doctor_standalone() -> Result<()> {
    let mut missing = Vec::new();
    check_tool("git", &mut missing);
    check_tool("docker", &mut missing);
    check_optional_tool("trivy", "scan/publish");
    check_optional_tool("pg_dump", "database backup");
    check_optional_tool("pg_restore", "database verification/restore");
    check_optional_tool("psql", "database target/version preflight");
    println!(
        "config\tnone\ttool availability only; engine connectivity and project paths not checked"
    );
    if !missing.is_empty() {
        bail!("missing or unavailable tools: {}", missing.join(", "));
    }
    Ok(())
}

fn doctor(loaded: &LoadedConfig) -> Result<()> {
    let mut missing = Vec::new();
    check_tool("git", &mut missing);
    for engine in [Engine::Docker, Engine::Podman] {
        if loaded
            .config
            .workloads
            .iter()
            .any(|item| item.engine == engine)
        {
            check_tool(engine.program(), &mut missing);
        }
    }
    check_optional_tool("trivy", "scan --execute");
    if loaded.config.postgres.is_some() {
        check_optional_tool("pg_dump", "database commands");
        check_optional_tool("pg_restore", "database commands");
        check_optional_tool("psql", "database target/version preflight");
    }
    println!(
        "config\tok\t{} workloads in {}",
        loaded.config.workloads.len(),
        loaded.root.display()
    );
    if !missing.is_empty() {
        bail!("missing or unavailable tools: {}", missing.join(", "));
    }
    Ok(())
}

fn check_optional_tool(program: &str, purpose: &str) {
    let status = Command::new(program).arg("--version").status();
    match status {
        Ok(status) if status.success() => println!("{program}\tok\toptional"),
        _ => println!("{program}\tmissing\toptional (required only for {purpose})"),
    }
}

fn check_tool(program: &str, missing: &mut Vec<String>) {
    let status = Command::new(program).arg("--version").status();
    match status {
        Ok(status) if status.success() => println!("{program}\tok"),
        _ => {
            println!("{program}\tmissing");
            missing.push(program.to_owned());
        }
    }
}

fn build(
    loaded: &LoadedConfig,
    name: &str,
    requested_commit: Option<&str>,
    build_args: &[String],
    execute: bool,
) -> Result<()> {
    let workload = loaded.workload(name)?;
    let commit = match requested_commit {
        Some(commit) => commit.to_owned(),
        None => git_head(&loaded.root)?,
    };
    validate_commit(&commit)?;
    let plan = build_plan(loaded, workload, &commit, build_args)?;
    println!("source\t{commit}");
    println!("image\t{}", image_ref(loaded, workload, &commit));
    println!("command\t{}", plan.display());
    if execute {
        plan.run()?;
        println!("result\tbuilt");
    } else {
        println!("result\tplan-only (pass --execute to build)");
    }
    Ok(())
}

fn resolve_commit(loaded: &LoadedConfig, requested: Option<&str>) -> Result<String> {
    let commit = match requested {
        Some(commit) => commit.to_owned(),
        None => git_head(&loaded.root)?,
    };
    validate_commit(&commit)?;
    Ok(commit)
}

fn verify(loaded: &LoadedConfig, name: &str, requested_commit: Option<&str>) -> Result<()> {
    let workload = loaded.workload(name)?;
    let commit = resolve_commit(loaded, requested_commit)?;
    let image = image_ref(loaded, workload, &commit);
    let plan = ProcessPlan::new(workload.engine.program())
        .arg("image")
        .arg("inspect")
        .arg(&image);
    let output = plan
        .output()
        .with_context(|| format!("cannot inspect image {image}"))?;
    verify_inspection(&output, &commit, workload.kind.as_str())?;
    println!("image\t{image}");
    println!("revision\t{commit}");
    println!("component\t{}", workload.kind.as_str());
    println!("result\tverified");
    Ok(())
}

fn verify_inspection(raw: &[u8], commit: &str, component: &str) -> Result<()> {
    let documents: Vec<Value> =
        serde_json::from_slice(raw).context("invalid image inspection JSON")?;
    let labels = documents
        .first()
        .and_then(|image| image.pointer("/Config/Labels"))
        .and_then(Value::as_object)
        .context("image has no OCI labels")?;
    let actual_revision = labels
        .get("org.opencontainers.image.revision")
        .and_then(Value::as_str);
    let actual_component = labels
        .get("org.opencontainers.image.source-component")
        .and_then(Value::as_str);
    if actual_revision != Some(commit) {
        bail!(
            "image revision mismatch: expected {commit}, found {:?}",
            actual_revision
        );
    }
    if actual_component != Some(component) {
        bail!(
            "image component mismatch: expected {component}, found {:?}",
            actual_component
        );
    }
    Ok(())
}

fn scan(
    loaded: &LoadedConfig,
    name: &str,
    requested_commit: Option<&str>,
    ignore_unfixed: bool,
    os_only: bool,
    execute: bool,
) -> Result<()> {
    let workload = loaded.workload(name)?;
    let commit = resolve_commit(loaded, requested_commit)?;
    let image = image_ref(loaded, workload, &commit);
    let plan = scan_plan(&image, ignore_unfixed, os_only);
    println!("image\t{image}");
    println!("command\t{}", plan.display());
    let secrets = publish::secret_scan_plan(&image);
    println!("secret_command\t{}", secrets.display());
    if execute {
        verify(loaded, name, Some(&commit))?;
        let scan = plan.capture_isolated()?;
        ensure!(
            scan.status.success(),
            "vulnerability scan failed ({}); captured output withheld",
            scan.status
        );
        publish::validate_scan(&serde_json::from_slice(&scan.stdout)?, &image)?;
        let scan = secrets.capture_isolated()?;
        ensure!(
            scan.status.success(),
            "secret scan failed ({}); captured output withheld",
            scan.status
        );
        publish::validate_secret_scan(&serde_json::from_slice(&scan.stdout)?, &image)?;
        println!("result\tscan-passed");
    } else {
        println!("result\tplan-only (pass --execute to scan)");
    }
    Ok(())
}

fn scan_plan(image: &str, ignore_unfixed: bool, os_only: bool) -> ProcessPlan {
    publish::scan_plan(image, ignore_unfixed, os_only)
}

fn quality(
    profile: &Path,
    report_root: &Path,
    group: Option<&str>,
    component: Option<&str>,
    suite: Option<&str>,
    report: Option<&Path>,
    execute: bool,
) -> Result<()> {
    let filter = runner::Filter {
        group: group.map(str::to_owned),
        component: component.map(str::to_owned),
        suite: suite.map(str::to_owned),
    };
    println!("profile\t{}", profile.display());
    println!("engine\tembedded-veriv");
    if !execute {
        println!("result\tplan-only (pass --execute to run verification)");
        return Ok(());
    }
    let outcome = runner::run(profile, &filter).map_err(anyhow::Error::msg)?;
    for result in &outcome.results {
        println!(
            "{}\t{}/{}\t{}\t{:.2}s",
            if result.passed { "PASS" } else { "FAIL" },
            result.group,
            result.suite,
            result.name,
            result.seconds
        );
        if !result.detail.is_empty() {
            println!("{}", result.detail);
        }
    }
    if let Some(report) = report {
        let report = config::contained_new_file(report_root, report)?;
        runner::write_report(&report, &outcome).map_err(anyhow::Error::msg)?;
        println!("report\t{}", report.display());
    }
    println!(
        "summary\t{}/{} checks passed",
        outcome.passed, outcome.total
    );
    if outcome.failed > 0 {
        bail!("{} verification checks failed", outcome.failed);
    }
    println!("result\tquality-passed");
    Ok(())
}

fn git_head(root: &Path) -> Result<String> {
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(root)
        .output()
        .context("failed to read repository HEAD")?;
    if !output.status.success() {
        bail!("project root is not a readable Git repository; pass --commit explicitly");
    }
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}

fn validate_commit(commit: &str) -> Result<()> {
    if commit.len() != 40 || !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("commit must be an exact 40-character hexadecimal SHA");
    }
    Ok(())
}

fn image_ref(loaded: &LoadedConfig, workload: &Workload, commit: &str) -> String {
    let local = format!(
        "{}/{}:{}",
        loaded.config.project.name, workload.name, commit
    );
    workload
        .registry
        .as_ref()
        .map(|registry| format!("{}/{local}", registry.trim_end_matches('/')))
        .unwrap_or(local)
}

fn build_plan(
    loaded: &LoadedConfig,
    workload: &Workload,
    commit: &str,
    build_args: &[String],
) -> Result<ProcessPlan> {
    let dockerfile = loaded.resolve_file(&workload.dockerfile)?;
    let context = loaded.resolve_dir(&workload.context)?;
    let image = image_ref(loaded, workload, commit);
    let revision = format!("org.opencontainers.image.revision={commit}");
    let component = format!(
        "org.opencontainers.image.source-component={}",
        workload.kind.as_str()
    );
    let platform = &workload.platforms[0];

    let mut plan = match workload.engine {
        Engine::Docker => ProcessPlan::new("docker")
            .arg("buildx")
            .arg("build")
            .arg("--file")
            .arg(dockerfile)
            .arg("--platform")
            .arg(platform)
            .arg("--label")
            .arg(revision)
            .arg("--label")
            .arg(component)
            .arg("--tag")
            .arg(image)
            .arg("--load"),
        Engine::Podman => ProcessPlan::new("podman")
            .arg("build")
            .arg("--file")
            .arg(dockerfile)
            .arg("--platform")
            .arg(platform)
            .arg("--label")
            .arg(revision)
            .arg("--label")
            .arg(component)
            .arg("--tag")
            .arg(image),
    };
    for build_arg in build_args {
        plan = plan.arg("--build-arg").arg(build_arg);
    }
    Ok(plan.arg(context))
}

fn check_plan(
    loaded: &LoadedConfig,
    workload: &Workload,
    target: &str,
    build_args: &[String],
) -> Result<ProcessPlan> {
    let dockerfile = loaded.resolve_file(&workload.dockerfile)?;
    let context = loaded.resolve_dir(&workload.context)?;
    let mut plan = match workload.engine {
        Engine::Docker => ProcessPlan::new("docker")
            .arg("buildx")
            .arg("build")
            .arg("--output")
            .arg("type=cacheonly"),
        Engine::Podman => ProcessPlan::new("podman").arg("build"),
    }
    .arg("--pull")
    .arg("--file")
    .arg(dockerfile)
    .arg("--platform")
    .arg(&workload.platforms[0])
    .arg("--target")
    .arg(target);
    for build_arg in build_args {
        plan = plan.arg("--build-arg").arg(build_arg);
    }
    Ok(plan.arg(context))
}

fn parse_target(value: &str) -> std::result::Result<String, String> {
    if value.is_empty()
        || !value.starts_with(|c: char| c.is_ascii_alphanumeric())
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
    {
        return Err("target must be a Dockerfile stage name".into());
    }
    Ok(value.to_owned())
}

fn parse_build_arg(value: &str) -> std::result::Result<String, String> {
    let (name, _) = value
        .split_once('=')
        .ok_or("build arg must be NAME=VALUE")?;
    if !name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err("build arg name must be an ASCII identifier".into());
    }
    if name.to_ascii_uppercase().split('_').any(|part| {
        matches!(
            part,
            "PASSWORD" | "PASSWD" | "TOKEN" | "SECRET" | "KEY" | "APIKEY" | "PRIVATEKEY"
        )
    }) {
        return Err("build args are not for secrets; use build secrets instead".into());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quality_accepts_an_explicit_profile_without_project_config() {
        let parsed = Cli::try_parse_from([
            "devops-tool",
            "quality",
            "--profile",
            "examples/demo/checks.toml",
            "--suite",
            "unit",
        ])
        .unwrap();
        assert!(parsed.config.is_none());
        let Commands::Quality {
            profile,
            suite,
            execute,
            ..
        } = parsed.command
        else {
            panic!("expected quality command")
        };
        assert_eq!(profile, Some(PathBuf::from("examples/demo/checks.toml")));
        assert_eq!(suite.as_deref(), Some("unit"));
        assert!(!execute);
    }

    #[test]
    fn scan_policy_is_explicit_and_defaults_to_all_findings() {
        let parsed =
            Cli::try_parse_from(["devops-tool", "scan", "--ignore-unfixed", "--os-only"]).unwrap();
        let Commands::Scan {
            ignore_unfixed,
            os_only,
            ..
        } = parsed.command
        else {
            panic!("expected scan command")
        };
        assert!(ignore_unfixed);
        assert!(os_only);
        assert!(
            scan_plan("test/app:sha", true, true)
                .args
                .contains(&"--ignore-unfixed".into())
        );
        assert!(
            scan_plan("test/app:sha", true, true)
                .args
                .windows(2)
                .any(|pair| pair == ["--pkg-types", "os"])
        );
        assert!(
            !scan_plan("test/app:sha", false, false)
                .args
                .contains(&"--ignore-unfixed".into())
        );
    }

    #[test]
    fn build_accepts_no_config_and_typed_overrides() {
        let parsed = Cli::try_parse_from([
            "devops-tool",
            "build",
            "--context",
            "a project/web",
            "--kind",
            "frontend",
        ])
        .unwrap();
        assert!(parsed.config.is_none());
        let Commands::Build {
            workload,
            options,
            execute,
            ..
        } = parsed.command
        else {
            panic!("expected build command");
        };
        assert!(workload.is_none());
        assert!(!execute);
        assert_eq!(options.context, Some(PathBuf::from("a project/web")));
        assert_eq!(options.kind.unwrap().as_str(), "frontend");
        assert!(Cli::try_parse_from(["devops-tool", "build", "--engine", "shell"]).is_err());
        assert!(Cli::try_parse_from(["devops-tool", "doctor"]).is_ok());
    }

    #[test]
    fn build_args_are_repeatable_and_reject_secret_names() {
        let parsed = Cli::try_parse_from([
            "devops-tool",
            "build",
            "--build-arg",
            "VITE_APP_ENV=development",
            "--build-arg",
            "VITE_API_URL=https://example.test/api?x=y",
        ])
        .unwrap();
        let Commands::Build { build_args, .. } = parsed.command else {
            panic!("expected build")
        };
        assert_eq!(
            build_args,
            [
                "VITE_APP_ENV=development",
                "VITE_API_URL=https://example.test/api?x=y"
            ]
        );
        for invalid in [
            "NO_EQUALS",
            "1BAD=value",
            "API_TOKEN=secret",
            "EMPTY NAME=value",
        ] {
            assert!(Cli::try_parse_from(["devops-tool", "build", "--build-arg", invalid]).is_err());
        }
        assert!(
            Cli::try_parse_from(["devops-tool", "build", "--build-arg", "MONKEY_MODE=on"]).is_ok()
        );
    }

    #[test]
    fn build_plan_passes_each_arg_without_printing_values() {
        let loaded = LoadedConfig::load(Path::new("examples/demo/devops.toml")).unwrap();
        let workload = loaded.workload("web").unwrap();
        let args = [
            "VITE_APP_ENV=development".to_owned(),
            "VITE_API_URL=https://dev.example.test/api".to_owned(),
        ];
        let plan = build_plan(
            &loaded,
            workload,
            "0123456789abcdef0123456789abcdef01234567",
            &args,
        )
        .unwrap();
        assert!(
            plan.args
                .windows(2)
                .any(|pair| pair == ["--build-arg", "VITE_APP_ENV=development"])
        );
        assert!(
            plan.args
                .windows(2)
                .any(|pair| pair == ["--build-arg", "VITE_API_URL=https://dev.example.test/api"])
        );
        assert!(!plan.display().contains("https://dev.example.test/api"));
    }

    #[test]
    fn check_uses_selected_stage_without_tag_or_load() {
        let parsed = Cli::try_parse_from([
            "devops-tool",
            "check",
            "--target",
            "test",
            "--build-arg",
            "VITE_APP_ENV=development",
        ])
        .unwrap();
        let Commands::Check {
            target,
            build_args,
            execute,
            ..
        } = parsed.command
        else {
            panic!("expected check command")
        };
        assert_eq!(target, "test");
        assert!(!execute);
        let loaded = LoadedConfig::load(Path::new("examples/demo/devops.toml")).unwrap();
        let plan = check_plan(
            &loaded,
            loaded.workload("web").unwrap(),
            &target,
            &build_args,
        )
        .unwrap();
        assert!(
            plan.args
                .windows(2)
                .any(|pair| pair == ["--target", "test"])
        );
        assert!(
            !plan
                .args
                .iter()
                .any(|arg| arg == "--tag" || arg == "--load" || arg == "--push")
        );
        assert!(
            plan.args
                .windows(2)
                .any(|pair| pair == ["--output", "type=cacheonly"])
        );
        assert!(plan.display().contains("VITE_APP_ENV=<redacted>"));
        assert!(Cli::try_parse_from(["devops-tool", "check", "--target", "--push"]).is_err());
        assert!(Cli::try_parse_from(["devops-tool", "check", "--target", "../test"]).is_err());
    }

    #[test]
    fn accepts_only_full_commit_ids() {
        assert!(validate_commit("0123456789abcdef0123456789abcdef01234567").is_ok());
        assert!(validate_commit("0123456").is_err());
        assert!(validate_commit("z123456789abcdef0123456789abcdef01234567").is_err());
    }

    #[test]
    fn workload_commands_share_config_free_options() {
        for command in ["validate", "verify", "scan", "publish"] {
            let mut args = vec![
                "devops-tool",
                command,
                "--context",
                "web app",
                "--kind",
                "frontend",
                "--registry",
                "localhost:5000/team",
            ];
            if command == "publish" {
                args.extend(["--evidence-dir", "private evidence"]);
            }
            assert!(Cli::try_parse_from(args).is_ok(), "{command}");
        }
    }

    #[test]
    fn publish_accepts_file_and_explicit_scan_policy_without_config() {
        let parsed = Cli::try_parse_from([
            "devops-tool",
            "publish",
            "--context",
            "app",
            "--kind",
            "frontend",
            "--registry",
            "localhost:5000",
            "--evidence-dir",
            "private evidence",
            "--build-arg-file",
            "app/ci/build.env",
            "--ignore-unfixed",
            "--os-only",
        ])
        .unwrap();
        assert!(parsed.config.is_none());
        let Commands::Publish {
            build_arg_file,
            ignore_unfixed,
            os_only,
            ..
        } = parsed.command
        else {
            panic!("expected publish command")
        };
        assert_eq!(build_arg_file, Some(PathBuf::from("app/ci/build.env")));
        assert!(ignore_unfixed && os_only);
    }

    #[test]
    fn rejects_image_with_wrong_revision() {
        let raw = br#"[{"Config":{"Labels":{"org.opencontainers.image.revision":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","org.opencontainers.image.source-component":"backend"}}}]"#;
        assert!(
            verify_inspection(raw, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "backend").is_err()
        );
    }

    #[test]
    fn accepts_matching_image_evidence() {
        let sha = "0123456789abcdef0123456789abcdef01234567";
        let raw = format!(
            r#"[{{"Config":{{"Labels":{{"org.opencontainers.image.revision":"{sha}","org.opencontainers.image.source-component":"frontend"}}}}}}]"#
        );
        assert!(verify_inspection(raw.as_bytes(), sha, "frontend").is_ok());
    }
}
