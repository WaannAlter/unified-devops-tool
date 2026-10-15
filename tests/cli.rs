use std::fs;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

struct Project(PathBuf);

impl Project {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "container workflow {} {} {}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed),
        ));
        fs::create_dir(&path).unwrap();
        fs::write(path.join("Dockerfile"), "FROM scratch\n").unwrap();
        Self(path)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_devops-tool"))
            .current_dir(&self.0)
            .args(args)
            .output()
            .unwrap()
    }

    fn config(&self, extra_workload: &str) {
        fs::write(self.0.join("devops.toml"), format!(
            "schema=1\n[project]\nname='demo'\n[[workloads]]\nname='app'\nkind='backend'\nengine='docker'\ndockerfile='Dockerfile'\ncontext='.'\n{extra_workload}"
        )).unwrap();
    }
}

impl Drop for Project {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn conventional_project_validates_and_previews_without_git_or_docker() {
    let project = Project::new();
    assert!(project.run(&["validate"]).status.success());
    let output = project.run(&[
        "build",
        "--commit",
        "0123456789abcdef0123456789abcdef01234567",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("plan-only"));
    assert!(text.contains("linux/amd64"));
    assert!(text.contains("Dockerfile"));
    assert!(!project.0.join(".git").exists());
}

#[test]
fn explicit_missing_configuration_does_not_fall_back() {
    let project = Project::new();
    assert!(
        !project
            .run(&["--config", "missing.toml", "validate"])
            .status
            .success()
    );
}

#[test]
fn paths_outside_the_project_are_rejected() {
    let project = Project::new();
    let output = project.run(&[
        "build",
        "--context",
        "..",
        "--dockerfile",
        "Dockerfile",
        "--commit",
        "0123456789abcdef0123456789abcdef01234567",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("escapes the project root"));
}

#[test]
fn unknown_configuration_keys_fail_closed() {
    let project = Project::new();
    project.config("unexpected=true\n");
    let output = project.run(&["validate"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown field"));
}

#[test]
fn multiple_workloads_validate_together_but_build_requires_selection() {
    let project = Project::new();
    project.config("[[workloads]]\nname='other'\nkind='frontend'\nengine='docker'\ndockerfile='Dockerfile'\ncontext='.'\n");
    assert!(project.run(&["validate"]).status.success());
    assert!(
        !project
            .run(&[
                "build",
                "--commit",
                "0123456789abcdef0123456789abcdef01234567"
            ])
            .status
            .success()
    );
    assert!(
        project
            .run(&[
                "build",
                "--workload",
                "other",
                "--commit",
                "0123456789abcdef0123456789abcdef01234567"
            ])
            .status
            .success()
    );
}

#[test]
fn argument_values_are_hidden_and_test_stage_is_not_tagged() {
    let project = Project::new();
    let output = project.run(&[
        "check",
        "--target",
        "test",
        "--build-arg",
        "MESSAGE=synthetic content",
    ]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("MESSAGE=<redacted>"));
    assert!(text.contains("cacheonly"));
    assert!(!text.contains("synthetic content"));
    assert!(!text.contains("--tag"));
}

#[cfg(unix)]
#[test]
fn symlink_to_an_outside_context_is_rejected() {
    let project = Project::new();
    std::os::unix::fs::symlink(project.0.parent().unwrap(), project.0.join("outside")).unwrap();
    assert!(
        !project
            .run(&[
                "build",
                "--context",
                "outside",
                "--commit",
                "0123456789abcdef0123456789abcdef01234567"
            ])
            .status
            .success()
    );
}
