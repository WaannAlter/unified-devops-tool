use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// Reuse the platform's process-group supervisor rather than implementing a
/// second subprocess/cancellation engine. exec keeps the CI-visible PID; timeout
/// forwards termination and kills remaining group members after the grace period.
/// This is an operational deadline, not an authorization/security boundary.
pub fn supervise(seconds: u64) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;
        let parent = std::fs::read_to_string("/proc/self/status")?
            .lines()
            .find_map(|line| line.strip_prefix("PPid:").map(str::trim))
            .context("Linux supervisor cannot identify parent")?
            .to_owned();
        if std::env::var("DEVOPS_TOOL_SUPERVISED").ok().as_deref() != Some(&parent) {
            let error = Command::new("timeout")
                .args(["-s", "TERM", "-k", "10"])
                .arg(seconds.to_string())
                .arg(std::env::current_exe()?)
                .args(std::env::args_os().skip(1))
                .env("DEVOPS_TOOL_SUPERVISED", std::process::id().to_string())
                .exec();
            bail!("cannot start Linux operation supervisor (timeout is required): {error}");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = seconds;
    Ok(())
}

#[derive(Debug, Eq, PartialEq)]
pub struct ProcessPlan {
    pub program: OsString,
    pub args: Vec<OsString>,
    env: Vec<(OsString, OsString)>,
    input: Option<PathBuf>,
    input_bytes: Option<Vec<u8>>,
    removed_env_prefixes: Vec<String>,
}

impl ProcessPlan {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            input: None,
            input_bytes: None,
            removed_env_prefixes: Vec::new(),
        }
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn arg(mut self, value: impl Into<OsString>) -> Self {
        self.args.push(value.into());
        self
    }

    pub fn input_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.input = Some(path.into());
        self.input_bytes = None;
        self
    }

    pub fn input_bytes(mut self, bytes: Vec<u8>) -> Self {
        self.input = None;
        self.input_bytes = Some(bytes);
        self
    }

    pub fn without_env_prefix(mut self, prefix: &str) -> Self {
        self.removed_env_prefixes.push(prefix.to_ascii_uppercase());
        self
    }

    fn command(&self) -> Result<Command> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        for (name, _) in std::env::vars_os().chain(self.env.iter().cloned()) {
            if self.removed_env_prefixes.iter().any(|prefix| {
                name.to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with(prefix)
            }) {
                command.env_remove(name);
            }
        }
        if let Some(path) = &self.input {
            command.stdin(Stdio::from(File::open(path)?));
        }
        Ok(command)
    }

    pub fn capture(&self) -> Result<Output> {
        if let Some(bytes) = &self.input_bytes {
            let mut child = self
                .command()?
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))?;
            let mut stdin = child.stdin.take().context("child stdin unavailable")?;
            return std::thread::scope(|scope| {
                // Drain output while writing input so neither pipe can deadlock.
                let writer = scope.spawn(move || stdin.write_all(bytes));
                let output = child.wait_with_output();
                writer
                    .join()
                    .map_err(|_| anyhow::anyhow!("stdin writer failed"))??;
                Ok(output?)
            });
        }
        self.command()?
            .output()
            .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))
    }

    /// Older scanners fall back to cwd files even when passed empty config paths.
    pub fn capture_isolated(&self) -> Result<Output> {
        let path = std::env::temp_dir().join(format!(
            "devops-scan-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        #[allow(unused_mut)]
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder
            .create(&path)
            .context("cannot create isolated scanner directory")?;
        let result = (|| {
            #[cfg(windows)]
            protect_new_directory(&path)?;
            ensure_empty_directory(&path)?;
            self.command()?
                .current_dir(&path)
                .output()
                .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))
        })();
        // Never recursively delete files unexpectedly created by a scanner.
        std::fs::remove_dir(&path)
            .context("isolated scanner directory retained; inspect before cleanup")?;
        result
    }

    pub fn display(&self) -> String {
        std::iter::once(self.program.to_string_lossy().into_owned())
            .chain(self.args.iter().enumerate().map(|(index, arg)| {
                if index > 0 && self.args[index - 1] == "--build-arg" {
                    let name = arg.to_string_lossy();
                    format!(
                        "{}=<redacted>",
                        name.split_once('=').map_or("?", |(name, _)| name)
                    )
                } else {
                    redacted_arg(arg)
                }
            }))
            .map(quote)
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn run(&self) -> Result<ExitStatus> {
        let status = self
            .command()?
            .status()
            .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))?;
        if !status.success() {
            bail!("command failed with {status}");
        }
        Ok(status)
    }

    pub fn run_stdout_to_stderr(&self) -> Result<ExitStatus> {
        let status = self
            .command()?
            .stdout(Stdio::from(std::io::stderr()))
            .status()
            .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))?;
        if !status.success() {
            bail!("command failed with {status}");
        }
        Ok(status)
    }

    pub fn run_to_files(&self, stdout: File, stderr: File) -> Result<ExitStatus> {
        let mut child = self
            .command()?
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .spawn()
            .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))?;
        let started = Instant::now();
        let mut next_report = 60;
        eprintln!("Build started; verbose output is retained in private evidence.");
        loop {
            if let Some(status) = child.try_wait()? {
                eprintln!(
                    "Build finished after {}s ({status}).",
                    started.elapsed().as_secs()
                );
                return Ok(status);
            }
            let elapsed = started.elapsed().as_secs();
            if elapsed >= next_report {
                eprintln!("Build still running ({elapsed}s); private evidence is being updated.");
                next_report = elapsed + 60;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    pub fn output(&self) -> Result<Vec<u8>> {
        let output = self.capture()?;
        if !output.status.success() {
            bail!("command failed with {}", output.status);
        }
        Ok(output.stdout)
    }
}

fn ensure_empty_directory(path: &std::path::Path) -> Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    if !meta.is_dir() || meta.file_type().is_symlink() || std::fs::read_dir(path)?.next().is_some()
    {
        bail!("isolated scanner directory must be empty and not a symlink");
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn protect_new_directory(path: &std::path::Path) -> Result<()> {
    ProcessPlan::new("powershell.exe")
        .env("DEVOPS_TOOL_SCAN_DIR", path)
        .arg("-NoProfile").arg("-NonInteractive").arg("-Command")
        .arg(r#"
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[System.IO.Directory]::SetAccessControl($env:DEVOPS_TOOL_SCAN_DIR, $acl)
$actual = [System.IO.Directory]::GetAccessControl($env:DEVOPS_TOOL_SCAN_DIR)
$rules = $actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].IsInherited -or
    $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
    throw 'scanner directory DACL verification failed'
}
"#).output().context("cannot protect isolated scanner directory")?;
    require_private_path(path)
}

#[cfg(windows)]
pub(crate) fn require_private_path(path: &std::path::Path) -> Result<()> {
    ProcessPlan::new("powershell.exe")
        .env("DEVOPS_TOOL_PRIVATE_PATH", path)
        .arg("-NoProfile").arg("-NonInteractive").arg("-Command")
        .arg(r#"
$ErrorActionPreference = 'Stop'
$path = $env:DEVOPS_TOOL_PRIVATE_PATH
$item = Get-Item -LiteralPath $path -Force
if ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) { throw 'reparse point refused' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = Get-Acl -LiteralPath $path
if ($acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'unexpected private state owner' }
$rules = $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
$ownerAllowed = $false
foreach ($rule in $rules) {
    if ($rule.AccessControlType -eq 'Allow') {
        if ($rule.IdentityReference.Value -ne $sid.Value) { throw 'private state grants another identity access' }
        $ownerAllowed = $true
    }
}
if (-not $ownerAllowed) { throw 'private state has no owner allow rule' }
"#).output().context("private state must be owned by and accessible only to the current Windows user")?;
    Ok(())
}

fn redacted_arg(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if let Some((key, _)) = value.split_once('=') {
        let key = key.to_ascii_lowercase();
        if ["password", "passwd", "token", "secret", "key"]
            .iter()
            .any(|part| key.contains(part))
        {
            return format!("{key}=<redacted>");
        }
    }
    value.into_owned()
}

fn quote(value: String) -> String {
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_bytes_preserve_exact_payload() {
        #[cfg(windows)]
        let plan = ProcessPlan::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg("[Console]::OpenStandardInput().CopyTo([Console]::OpenStandardOutput())");
        #[cfg(not(windows))]
        let plan = ProcessPlan::new("cat");
        let bytes = b"{\"checked\":true}\n\x00unchanged".to_vec();
        let output = plan.input_bytes(bytes.clone()).capture().unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, bytes);
    }

    #[test]
    fn scanner_runs_from_an_empty_private_directory_and_cleans_it_up() {
        #[cfg(windows)]
        let plan = ProcessPlan::new("powershell.exe")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg("[Console]::Write((Get-Location).Path)");
        #[cfg(not(windows))]
        let plan = ProcessPlan::new("pwd");
        let output = plan.capture_isolated().unwrap();
        assert!(output.status.success());
        let path = PathBuf::from(String::from_utf8(output.stdout).unwrap().trim());
        assert_ne!(path, std::env::current_dir().unwrap());
        assert!(
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("devops-scan-")
        );
        assert!(!path.exists());
    }

    #[cfg(windows)]
    #[test]
    fn private_windows_state_refuses_broad_acl_without_modifying_it() {
        let path = std::env::temp_dir().join(format!(
            "devops-acl-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::write(&path, b"unchanged").unwrap();
        crate::database::secure_permissions(&path).unwrap();
        require_private_path(&path).unwrap();
        ProcessPlan::new("icacls.exe")
            .arg(&path)
            .arg("/grant")
            .arg("*S-1-1-0:R")
            .output()
            .unwrap();
        assert!(require_private_path(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"unchanged");
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn policy_environment_cannot_be_reintroduced_by_overrides() {
        let plan = ProcessPlan::new("trivy")
            .env("TRIVY_SKIP_FILES", "everything")
            .env("trivy_ignorefile", "unsafe")
            .env("DOCKER_HOST", "preserved")
            .without_env_prefix("TRIVY_");
        let command = plan.command().unwrap();
        let env: Vec<_> = command.get_envs().collect();
        assert!(env.contains(&(OsStr::new("TRIVY_SKIP_FILES"), None)));
        assert!(env.contains(&(OsStr::new("trivy_ignorefile"), None)));
        assert!(env.contains(&(OsStr::new("DOCKER_HOST"), Some(OsStr::new("preserved")))));
    }

    #[test]
    fn empty_policy_arguments_are_visible_in_plans() {
        assert_eq!(
            ProcessPlan::new("trivy").arg("--config").arg("").display(),
            "trivy --config \"\""
        );
    }

    #[test]
    fn preserves_boundaries_and_redacts_secrets() {
        let plan = ProcessPlan::new("docker")
            .arg("--file")
            .arg(r"D:\a project\Dockerfile")
            .arg("API_TOKEN=do-not-print");
        assert_eq!(plan.args.len(), 3);
        assert_eq!(
            plan.display(),
            r#"docker --file "D:\a project\Dockerfile" api_token=<redacted>"#
        );
    }

    #[test]
    fn build_arg_values_are_executed_but_not_printed() {
        let plan = ProcessPlan::new("docker")
            .arg("buildx")
            .arg("--build-arg")
            .arg("VITE_API_URL=https://example.test/?token=demo");
        assert_eq!(
            plan.args[2],
            "VITE_API_URL=https://example.test/?token=demo"
        );
        assert_eq!(
            plan.display(),
            "docker buildx --build-arg VITE_API_URL=<redacted>"
        );
    }
}
