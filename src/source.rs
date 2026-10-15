use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

/// Immutable Git evidence used as a container build source.
#[derive(Debug)]
pub struct Snapshot {
    pub revision: String,
    pub tree: String,
    pub config_path: Option<PathBuf>,
    pub config_sha256: Option<String>,
    pub dockerfile: PathBuf,
    pub git_root: PathBuf,
    pub context: PathBuf,
}

impl Snapshot {
    /// Write the committed context tree to a new tar file and return its SHA-256.
    pub fn archive(&self, target: &Path) -> Result<String> {
        if fs::symlink_metadata(target).is_ok() {
            bail!("archive output {} already exists", target.display());
        }
        let parent = target
            .parent()
            .context("archive output has no parent directory")?;
        if !parent.is_dir() {
            bail!(
                "archive output directory {} does not exist",
                parent.display()
            );
        }

        // create_new closes the check/create race and refuses both files and links.
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(target)
            .with_context(|| format!("cannot create archive {}", target.display()))?;
        let treeish = if self.context.as_os_str().is_empty() {
            self.revision.clone()
        } else {
            format!("{}:{}", self.revision, git_path(&self.context))
        };
        let status = Command::new("git")
            // Match a 0022 checkout: Git's default tar umask (0002) otherwise
            // changes COPY checksums and rebuilds already-tested dependencies.
            .args(["-c", "tar.umask=0022"])
            .arg("archive")
            .arg("--format=tar")
            .arg(&treeish)
            .current_dir(&self.git_root)
            .stdout(Stdio::from(file))
            .status()
            .context("failed to start git archive");
        match status {
            Ok(status) if status.success() => sha256_file(target),
            Ok(status) => {
                let _ = fs::remove_file(target);
                bail!("git archive failed with {status}; incomplete archive removed")
            }
            Err(error) => {
                let _ = fs::remove_file(target);
                Err(error.context("incomplete archive removed"))
            }
        }
    }
}

pub fn inspect(
    loaded: &crate::config::LoadedConfig,
    workload: &crate::config::Workload,
    config_path: Option<&Path>,
    requested: &str,
) -> Result<Snapshot> {
    validate_revision(requested)?;
    let git_root = canonical_git_root(&loaded.root)?;
    if !loaded.root.starts_with(&git_root) {
        bail!(
            "project root {} is outside Git root {}",
            loaded.root.display(),
            git_root.display()
        );
    }
    let revision = git(&git_root, ["rev-parse", "HEAD"])?;
    if revision != requested {
        bail!("HEAD {revision} does not match requested revision {requested}");
    }
    ensure_clean(&git_root)?;

    let config = config_path
        .map(|path| {
            fs::canonicalize(path).with_context(|| format!("cannot open config {}", path.display()))
        })
        .transpose()?;
    let context = loaded.resolve_dir(&workload.context)?;
    let dockerfile = loaded.resolve_file(&workload.dockerfile)?;
    for (label, path) in [("context", &context), ("Dockerfile", &dockerfile)] {
        if !path.starts_with(&git_root) {
            bail!(
                "{label} {} is outside Git root {}",
                path.display(),
                git_root.display()
            );
        }
    }
    if !dockerfile.starts_with(&context) {
        bail!(
            "Dockerfile {} is outside build context {}",
            dockerfile.display(),
            context.display()
        );
    }

    let config_rel = config
        .as_deref()
        .map(|path| repo_relative(&git_root, path))
        .transpose()?;
    let context_rel = repo_relative(&git_root, &context)?;
    let dockerfile_rel = repo_relative(&git_root, &dockerfile)?;
    let dockerfile_in_context = dockerfile
        .strip_prefix(&context)
        .context("Dockerfile is outside build context")?
        .to_path_buf();
    let config_sha256 = if let (Some(path), Some(relative)) = (&config, &config_rel) {
        ensure_tracked(&git_root, relative)?;
        ensure_committed_content(&git_root, &revision, relative, path)?;
        Some(sha256_bytes(&normalize_lf(&fs::read(path)?)))
    } else {
        None
    };
    let tree = context_tree(&git_root, &revision, &context_rel)?;
    let context_entries = context_entries(&git_root, &revision, &context_rel)?;
    let mut archive_paths = vec![dockerfile_rel];
    archive_paths.extend(config_rel.iter().cloned());
    archive_paths.extend(context_entries);
    reject_archive_attributes(&git_root, &archive_paths)?;

    Ok(Snapshot {
        revision,
        tree,
        config_path: config_rel,
        config_sha256,
        dockerfile: dockerfile_in_context,
        git_root,
        context: context_rel,
    })
}

fn validate_revision(value: &str) -> Result<()> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("requested revision must be an exact lowercase 40-character SHA-1");
    }
    Ok(())
}

fn canonical_git_root(project_root: &Path) -> Result<PathBuf> {
    let root = git(project_root, ["rev-parse", "--show-toplevel"])
        .context("project root is not a readable Git repository")?;
    fs::canonicalize(root).context("cannot canonicalize Git root")
}

fn ensure_clean(root: &Path) -> Result<()> {
    let status = git(
        root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignore-submodules=none",
        ],
    )?;
    if !status.is_empty() {
        bail!("Git repository is not clean (tracked changes or untracked files are present)");
    }
    Ok(())
}

fn ensure_tracked(root: &Path, path: &Path) -> Result<()> {
    let output = Command::new("git")
        .arg("ls-files")
        .arg("--error-unmatch")
        .arg("--")
        .arg(literal_path(path))
        .current_dir(root)
        .output()
        .context("failed to inspect tracked config")?;
    if !output.status.success() {
        bail!("config {} is not tracked by Git", path.display());
    }
    Ok(())
}

fn ensure_committed_content(
    root: &Path,
    revision: &str,
    relative: &Path,
    file: &Path,
) -> Result<()> {
    let committed = git_bytes(
        root,
        vec![
            "show".into(),
            format!("{revision}:{}", git_path(relative)).into(),
        ],
    )
    .with_context(|| format!("cannot read committed config {}", relative.display()))?;
    let actual =
        fs::read(file).with_context(|| format!("cannot read config {}", file.display()))?;
    if normalize_lf(&committed) != normalize_lf(&actual) {
        bail!(
            "config {} differs from its committed content",
            file.display()
        );
    }
    Ok(())
}

fn reject_archive_attributes(root: &Path, paths: &[PathBuf]) -> Result<()> {
    let mut child = Command::new("git")
        .arg("check-attr")
        // Archive follows the committed tree; configured global attributes still apply.
        .arg("--cached")
        .arg("-z")
        .arg("--stdin")
        .arg("export-ignore")
        .arg("export-subst")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .context("failed to inspect Git archive attributes")?;
    let mut input = Vec::new();
    for path in paths {
        input.extend_from_slice(git_path(path).as_bytes());
        input.push(0);
    }
    let stdin = child.stdin.take().context("missing Git attribute stdin")?;
    let output = thread::scope(|scope| {
        let writer = scope.spawn(move || {
            let mut stdin = stdin;
            stdin.write_all(&input)
        });
        let output = child
            .wait_with_output()
            .context("failed to inspect Git archive attributes")?;
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git attribute input writer panicked"))??;
        Ok::<_, anyhow::Error>(output)
    })?;
    if !output.status.success() {
        bail!("failed to inspect Git archive attributes")
    }
    let mut fields = output.stdout.split(|byte| *byte == 0);
    while let (Some(_path), Some(attribute), Some(value)) =
        (fields.next(), fields.next(), fields.next())
    {
        if value != b"unspecified" && value != b"unset" {
            bail!(
                "{} has Git attribute {}={}, which is unsafe for source archives",
                String::from_utf8_lossy(_path),
                String::from_utf8_lossy(attribute),
                String::from_utf8_lossy(value)
            );
        }
    }
    Ok(())
}

fn context_tree(root: &Path, revision: &str, context: &Path) -> Result<String> {
    let object = if context.as_os_str().is_empty() {
        git_os(
            root,
            vec!["rev-parse".into(), format!("{revision}^{{tree}}").into()],
        )?
    } else {
        git_os(
            root,
            vec![
                "rev-parse".into(),
                format!("{revision}:{}", git_path(context)).into(),
            ],
        )?
    };
    let kind = git_os(
        root,
        vec!["cat-file".into(), "-t".into(), object.clone().into()],
    )?;
    if kind != "tree" {
        bail!(
            "build context {} is not a committed Git tree",
            context.display()
        );
    }
    Ok(object)
}

fn context_entries(root: &Path, revision: &str, context: &Path) -> Result<Vec<PathBuf>> {
    let mut command = Command::new("git");
    command.arg("ls-tree").arg("-r").arg("-z").arg(revision);
    if !context.as_os_str().is_empty() {
        command.arg("--").arg(literal_path(context));
    }
    let output = command
        .current_dir(root)
        .output()
        .context("failed to inspect context tree")?;
    if !output.status.success() {
        bail!("failed to inspect context tree")
    }
    let mut paths = Vec::new();
    for entry in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|entry| !entry.is_empty())
    {
        let mut fields = entry.splitn(2, |byte| *byte == b'\t');
        let header = fields.next().unwrap_or_default();
        let path = fields.next().unwrap_or_default();
        let mode = header
            .split(|byte| *byte == b' ')
            .next()
            .unwrap_or_default();
        if mode == b"120000" || mode == b"160000" {
            bail!(
                "build context contains unsupported {} entry",
                if mode == b"120000" {
                    "symlink"
                } else {
                    "gitlink/submodule"
                }
            );
        }
        let path = PathBuf::from(String::from_utf8_lossy(path).into_owned());
        add_path_and_parents(&mut paths, &path, context);
    }
    if !context.as_os_str().is_empty() {
        add_path_and_parents(&mut paths, context, context);
    }
    Ok(paths)
}

fn add_path_and_parents(paths: &mut Vec<PathBuf>, path: &Path, context: &Path) {
    let mut current = Some(path);
    while let Some(item) = current {
        if !paths.iter().any(|known| known == item) {
            paths.push(item.to_path_buf());
        }
        if item == context || item.as_os_str().is_empty() {
            break;
        }
        current = item.parent();
    }
}

fn repo_relative(root: &Path, path: &Path) -> Result<PathBuf> {
    path.strip_prefix(root)
        .map(Path::to_path_buf)
        .with_context(|| format!("{} is outside Git root {}", path.display(), root.display()))
}

fn literal_path(path: &Path) -> String {
    format!(":(literal){}", git_path(path))
}

fn git_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_lf(bytes: &[u8]) -> Vec<u8> {
    let mut normalized = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\r' && bytes.get(index + 1) == Some(&b'\n') {
            index += 1;
        }
        normalized.push(bytes[index]);
        index += 1;
    }
    normalized
}

fn git<'a>(root: &Path, args: impl AsRef<[&'a str]>) -> Result<String> {
    git_os(
        root,
        args.as_ref().iter().map(|arg| (*arg).into()).collect(),
    )
}

fn git_os(root: &Path, args: Vec<std::ffi::OsString>) -> Result<String> {
    let bytes = git_bytes(root, args)?;
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}

fn git_bytes(root: &Path, args: Vec<std::ffi::OsString>) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("failed to start git")?;
    if !output.status.success() {
        bail!("git command failed with {}", output.status);
    }
    Ok(output.stdout)
}

fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        fs::File::open(path).with_context(|| format!("cannot read {}", path.display()))?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Fixture {
        root: PathBuf,
        config: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "udt source {} {}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(root.join("app")).unwrap();
            fs::write(root.join("devops.toml"), "schema = 1\n[project]\nname = \"demo\"\nroot = \".\"\n[[workloads]]\nname = \"app\"\nkind = \"backend\"\nengine = \"docker\"\ndockerfile = \"app/Dockerfile\"\ncontext = \"app\"\n").unwrap();
            fs::write(root.join("app/Dockerfile"), "FROM scratch\n").unwrap();
            run(&root, &["init"]);
            run(&root, &["config", "user.email", "test@example.invalid"]);
            run(&root, &["config", "user.name", "Test"]);
            run(&root, &["add", "."]);
            run(&root, &["commit", "-m", "fixture"]);
            Self {
                config: root.join("devops.toml"),
                root,
            }
        }
        fn snapshot(&self) -> Result<Snapshot> {
            let loaded = crate::config::LoadedConfig::load(&self.config)?;
            let workload = loaded.workload("app")?;
            inspect(
                &loaded,
                workload,
                Some(&self.config),
                &git(&self.root, ["rev-parse", "HEAD"])?,
            )
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn run(root: &Path, args: &[&str]) {
        assert!(
            Command::new("git")
                .args(args)
                .current_dir(root)
                .status()
                .unwrap()
                .success()
        );
    }

    #[test]
    fn snapshots_and_archives_spaced_repository() {
        let fixture = Fixture::new();
        run(&fixture.root, &["config", "tar.umask", "0000"]);
        fs::write(fixture.root.join("app/run.sh"), "#!/bin/sh\nexit 0\n").unwrap();
        run(&fixture.root, &["add", "app/run.sh"]);
        run(&fixture.root, &["update-index", "--chmod=+x", "app/run.sh"]);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                fixture.root.join("app/run.sh"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        run(&fixture.root, &["commit", "-m", "executable fixture"]);
        let snapshot = fixture.snapshot().unwrap();
        assert_eq!(snapshot.dockerfile, PathBuf::from("Dockerfile"));
        let target = std::env::temp_dir().join(format!(
            "udt archive {}.tar",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let digest = snapshot.archive(&target).unwrap();
        assert_eq!(digest, sha256_file(&target).unwrap());
        let archive = fs::read(&target).unwrap();
        for (name, mode) in [
            (b"Dockerfile\0".as_slice(), 0o644),
            (b"run.sh\0".as_slice(), 0o755),
        ] {
            let header = archive
                .as_chunks::<512>()
                .0
                .iter()
                .find(|block| block.starts_with(name))
                .unwrap();
            let actual = std::str::from_utf8(&header[100..108])
                .unwrap()
                .trim_matches(['\0', ' ']);
            assert_eq!(u32::from_str_radix(actual, 8).unwrap(), mode);
        }
        assert!(target.exists());
        assert!(snapshot.archive(&target).is_err());
        let _ = fs::remove_file(target);
    }
    #[test]
    fn rejects_stale_dirty_and_untracked_inputs() {
        let fixture = Fixture::new();
        let loaded = crate::config::LoadedConfig::load(&fixture.config).unwrap();
        let workload = loaded.workload("app").unwrap();
        assert!(
            inspect(
                &loaded,
                workload,
                Some(&fixture.config),
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            )
            .is_err()
        );
        fs::write(fixture.root.join("app/Dockerfile"), "changed\n").unwrap();
        assert!(fixture.snapshot().is_err());
        run(&fixture.root, &["checkout", "--", "app/Dockerfile"]);
        fs::write(fixture.root.join("app/input"), "x").unwrap();
        assert!(fixture.snapshot().is_err());
    }
    #[test]
    fn rejects_untracked_config_and_dockerfile_outside_context() {
        let fixture = Fixture::new();
        let external = fixture.root.parent().unwrap().join("outside-devops.toml");
        fs::write(&external, "schema = 1").unwrap();
        let loaded = crate::config::LoadedConfig::load(&fixture.config).unwrap();
        let workload = loaded.workload("app").unwrap();
        let head = git(&fixture.root, ["rev-parse", "HEAD"]).unwrap();
        assert!(inspect(&loaded, workload, Some(&external), &head).is_err());
        let _ = fs::remove_file(external);
        fs::write(fixture.root.join("other.Dockerfile"), "FROM scratch\n").unwrap();
        // A direct workload is enough to exercise the source boundary before config validation.
        let outside = crate::config::Workload {
            name: "app".into(),
            kind: crate::config::WorkloadKind::Backend,
            engine: crate::config::Engine::Docker,
            dockerfile: "other.Dockerfile".into(),
            context: "app".into(),
            registry: None,
            platforms: vec!["linux/amd64".into()],
        };
        assert!(inspect(&loaded, &outside, Some(&fixture.config), &head).is_err());
    }

    #[test]
    fn rejects_gitlink_entries_in_committed_context() {
        let fixture = Fixture::new();
        let head = git(&fixture.root, ["rev-parse", "HEAD"]).unwrap();
        let cacheinfo = format!("160000,{head},app/module");
        run(
            &fixture.root,
            &["update-index", "--add", "--cacheinfo", &cacheinfo],
        );
        run(&fixture.root, &["commit", "-m", "gitlink"]);
        let revision = git(&fixture.root, ["rev-parse", "HEAD"]).unwrap();
        assert!(context_entries(&fixture.root, &revision, Path::new("app")).is_err());
    }

    #[test]
    fn rejects_export_attributes_anywhere_in_context() {
        let fixture = Fixture::new();
        fs::write(fixture.root.join("app/payload"), "payload\n").unwrap();
        fs::write(
            fixture.root.join(".gitattributes"),
            "app export-ignore\napp/payload export-subst\n",
        )
        .unwrap();
        run(&fixture.root, &["add", ".gitattributes", "app/payload"]);
        run(&fixture.root, &["commit", "-m", "unsafe attributes"]);
        assert!(fixture.snapshot().is_err());
    }
}
