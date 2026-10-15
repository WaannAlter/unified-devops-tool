use std::ffi::{OsStr, OsString};
use std::fs::File;
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
}

impl ProcessPlan {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            input: None,
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
        self
    }

    fn command(&self) -> Result<Command> {
        let mut command = Command::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().map(|(k, v)| (k, v)));
        if let Some(path) = &self.input {
            command.stdin(Stdio::from(File::open(path)?));
        }
        Ok(command)
    }

    pub fn capture(&self) -> Result<Output> {
        self.command()?
            .output()
            .with_context(|| format!("failed to start {}", self.program.to_string_lossy()))
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
    if value.chars().any(char::is_whitespace) {
        format!("\"{}\"", value.replace('"', "\\\""))
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
