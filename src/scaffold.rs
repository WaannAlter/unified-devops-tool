use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Component, Path, PathBuf};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, ValueEnum};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ScaffoldTemplate {
    Rust,
    NpmStatic,
    BunStatic,
}

#[derive(Args, Debug)]
pub struct ScaffoldOptions {
    #[arg(long, value_enum)]
    pub template: ScaffoldTemplate,
    #[arg(long, default_value = ".")]
    pub context: PathBuf,
    #[arg(long)]
    pub execute: bool,
    #[arg(long)]
    pub binary: Option<String>,
    #[arg(long, default_value_t = 8080)]
    pub port: u16,
    #[arg(long)]
    pub health_path: Option<String>,
}

pub fn run(options: &ScaffoldOptions) -> Result<()> {
    let context = validate_context(&options.context)?;
    ensure!(options.port != 0, "port must be in 1..=65535");
    if options.template != ScaffoldTemplate::Rust {
        ensure!(options.binary.is_none(), "--binary is only valid for Rust");
        ensure!(
            options.health_path.is_none(),
            "--health-path is only valid for Rust"
        );
    }
    if let Some(path) = &options.health_path {
        ensure!(
            path.starts_with('/') && !path.starts_with("//"),
            "health path must be a plain absolute path"
        );
        ensure!(
            path.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.~".contains(&b)),
            "health path must be a plain absolute path"
        );
        ensure!(
            !path.split('/').any(|part| part == "." || part == ".."),
            "health path cannot contain dot segments"
        );
    }

    let (dockerfile, nginx) = match options.template {
        ScaffoldTemplate::Rust => {
            let binary = rust_binary(&context, options.binary.as_deref())?;
            let mut dockerfile = include_str!("templates/scaffold/rust.Dockerfile")
                .replace("@BINARY@", &binary)
                .replace("@PORT@", &options.port.to_string());
            let (extra_packages, health) = if let Some(path) = &options.health_path {
                (
                    " curl",
                    format!(
                        "HEALTHCHECK --interval=30s --timeout=3s --start-period=10s CMD curl --fail --silent --show-error http://127.0.0.1:{}{} || exit 1",
                        options.port, path
                    ),
                )
            } else {
                ("", String::new())
            };
            dockerfile = dockerfile
                .replace("@EXTRA_PACKAGES@", extra_packages)
                .replace("@HEALTHCHECK@", &health);
            (dockerfile, None)
        }
        ScaffoldTemplate::NpmStatic | ScaffoldTemplate::BunStatic => {
            let has_test = static_package(&context, options.template)?;
            let source = if options.template == ScaffoldTemplate::NpmStatic {
                include_str!("templates/scaffold/npm.Dockerfile")
            } else {
                include_str!("templates/scaffold/bun.Dockerfile")
            };
            let test = match (options.template, has_test) {
                (ScaffoldTemplate::NpmStatic, true) => "RUN npm run test",
                (ScaffoldTemplate::BunStatic, true) => "RUN bun run test",
                _ => {
                    "RUN echo 'No test script in package.json; test target unavailable' >&2; exit 1"
                }
            };
            let dockerfile = source
                .replace("@TEST@", test)
                .replace("@PORT@", &options.port.to_string());
            let nginx = include_str!("templates/scaffold/nginx.conf")
                .replace("@PORT@", &options.port.to_string());
            (dockerfile, Some(nginx))
        }
    };
    let ignore = include_str!("templates/scaffold/dockerignore").to_owned();
    let compose = include_str!("templates/scaffold/compose.yaml")
        .replace("@PORT@", &options.port.to_string())
        .replace(
            "@USER@",
            if nginx.is_some() {
                "101:101"
            } else {
                "65532:65532"
            },
        )
        .replace(
            "@TMPFS@",
            if nginx.is_some() {
                "    tmpfs:\n      - /tmp:rw,noexec,nosuid,size=16m\n"
            } else {
                ""
            },
        );
    let mut outputs = vec![
        ("Dockerfile", dockerfile),
        (".dockerignore", ignore),
        ("compose.yaml", compose),
    ];
    if let Some(nginx) = nginx {
        outputs.push(("scaffold.nginx.conf", nginx));
    }
    for (name, _) in &outputs {
        ensure!(
            !fs::symlink_metadata(context.join(name)).is_ok(),
            "output already exists: {name}"
        );
    }
    if !options.execute {
        for (name, content) in &outputs {
            println!("--- {name} ---\n{content}");
        }
        return Ok(());
    }
    write_outputs(&context, &outputs)
}

fn write_outputs(context: &Path, outputs: &[(&str, String)]) -> Result<()> {
    let mut created = Vec::new();
    let result = (|| -> Result<()> {
        let mut files: Vec<File> = Vec::new();
        for (name, _) in outputs {
            let path = context.join(name);
            let file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .with_context(|| format!("reserve {}", path.display()))?;
            created.push(path);
            files.push(file);
        }
        for ((name, content), file) in outputs.iter().zip(files.iter_mut()) {
            file.write_all(content.as_bytes())
                .with_context(|| format!("write {name}"))?;
            file.sync_all().with_context(|| format!("sync {name}"))?;
        }
        Ok(())
    })();
    if result.is_err() {
        for path in &created {
            let _ = fs::remove_file(path);
        }
    }
    result
}

fn validate_context(path: &Path) -> Result<PathBuf> {
    ensure!(
        !path
            .components()
            .any(|part| matches!(part, Component::ParentDir)),
        "context cannot contain '..'"
    );
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let mut part_path = PathBuf::new();
    for part in absolute.components() {
        part_path.push(part);
        if let Ok(metadata) = fs::symlink_metadata(&part_path) {
            ensure!(
                !metadata.file_type().is_symlink(),
                "symlinked context component: {}",
                part_path.display()
            );
        }
    }
    ensure!(
        absolute.is_dir(),
        "context is not a directory: {}",
        absolute.display()
    );
    absolute.canonicalize().context("resolve context")
}

fn regular_input(context: &Path, name: &str) -> Result<String> {
    let path = context.join(name);
    let metadata =
        fs::symlink_metadata(&path).with_context(|| format!("missing required {name}"))?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "{name} must be a regular file, not a symlink"
    );
    fs::read_to_string(&path).with_context(|| format!("read {name}"))
}

fn safe_name(name: &str) -> bool {
    name.as_bytes()
        .first()
        .is_some_and(u8::is_ascii_alphanumeric)
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn binary_source(context: &Path, source: &Path) -> Result<bool> {
    ensure!(
        source
            .components()
            .all(|part| matches!(part, Component::Normal(_) | Component::CurDir)),
        "binary source must stay inside the context"
    );
    let mut path = context.to_owned();
    for part in source.components() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => ensure!(
                !metadata.file_type().is_symlink(),
                "symlinked binary source: {}",
                path.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error).with_context(|| format!("inspect {}", path.display())),
        }
    }
    Ok(path.is_file())
}

fn rust_binary(context: &Path, requested: Option<&str>) -> Result<String> {
    regular_input(context, "Cargo.lock")?;
    let manifest: toml::Value =
        toml::from_str(&regular_input(context, "Cargo.toml")?).context("invalid Cargo.toml")?;
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .context("Cargo.toml must define one package")?;
    ensure!(
        manifest
            .get("workspace")
            .and_then(|w| w.get("members"))
            .is_none(),
        "workspace members are not supported"
    );
    let package_name = package
        .get("name")
        .and_then(toml::Value::as_str)
        .context("package name missing")?;
    ensure!(
        safe_name(package_name),
        "package name is not safe for a Dockerfile"
    );
    let mut bins = Vec::new();
    let mut declared_paths = Vec::new();
    if let Some(entries) = manifest.get("bin") {
        for bin in entries.as_array().context("[[bin]] must be an array")? {
            let name = bin
                .get("name")
                .and_then(toml::Value::as_str)
                .context("[[bin]] name is required")?;
            ensure!(safe_name(name), "binary name is not safe for a Dockerfile");
            ensure!(
                !bins.iter().any(|existing| existing == name),
                "duplicate [[bin]] name: {name}"
            );
            if let Some(path) = bin.get("path") {
                let path = PathBuf::from(path.as_str().context("[[bin]] path must be a string")?);
                ensure!(
                    binary_source(context, &path)?,
                    "[[bin]] source does not exist: {}",
                    path.display()
                );
                declared_paths.push(path);
            }
            bins.push(name.to_owned());
        }
    }
    let auto_bins = package.get("autobins").and_then(toml::Value::as_bool) != Some(false);
    if auto_bins
        && binary_source(context, Path::new("src/main.rs"))?
        && !declared_paths
            .iter()
            .any(|path| path == Path::new("src/main.rs"))
        && !bins.iter().any(|name| name == package_name)
    {
        bins.push(package_name.to_owned());
    }
    let bin_dir = context.join("src/bin");
    if auto_bins && fs::symlink_metadata(&bin_dir).is_ok_and(|meta| meta.file_type().is_symlink()) {
        bail!("symlinked binary source: {}", bin_dir.display());
    }
    if auto_bins && bin_dir.is_dir() {
        for entry in fs::read_dir(bin_dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            ensure!(
                !kind.is_symlink(),
                "symlinked binary source: {}",
                entry.path().display()
            );
            let (name, source) =
                if kind.is_file() && entry.path().extension().is_some_and(|ext| ext == "rs") {
                    (
                        entry
                            .file_name()
                            .to_string_lossy()
                            .trim_end_matches(".rs")
                            .to_owned(),
                        PathBuf::from("src/bin").join(entry.file_name()),
                    )
                } else if kind.is_dir() {
                    (
                        entry.file_name().to_string_lossy().to_string(),
                        PathBuf::from("src/bin")
                            .join(entry.file_name())
                            .join("main.rs"),
                    )
                } else {
                    continue;
                };
            if binary_source(context, &source)? {
                ensure!(safe_name(&name), "binary name is not safe for a Dockerfile");
                if !declared_paths.contains(&source) && !bins.contains(&name) {
                    bins.push(name);
                }
            }
        }
    }
    bins.sort();
    bins.dedup();
    if let Some(name) = requested {
        ensure!(safe_name(name), "--binary must be a plain binary name");
        ensure!(
            bins.iter().any(|bin| bin == name),
            "--binary does not match a detected binary"
        );
        return Ok(name.to_owned());
    }
    match bins.as_slice() {
        [name] => Ok(name.clone()),
        [] => bail!("no binary detected; expected [[bin]] or src/main.rs"),
        _ => bail!("multiple binaries detected; select one with --binary"),
    }
}

fn static_package(context: &Path, template: ScaffoldTemplate) -> Result<bool> {
    let manifest: serde_json::Value =
        serde_json::from_str(&regular_input(context, "package.json")?)
            .context("invalid package.json")?;
    let scripts = manifest
        .get("scripts")
        .and_then(serde_json::Value::as_object)
        .context("package.json scripts.build is required")?;
    ensure!(
        scripts
            .get("build")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|s| !s.trim().is_empty()),
        "package.json scripts.build is required"
    );
    match template {
        ScaffoldTemplate::NpmStatic => {
            regular_input(context, "package-lock.json")?;
        }
        ScaffoldTemplate::BunStatic => {
            regular_input(context, "bun.lock")?;
        }
        ScaffoldTemplate::Rust => unreachable!(),
    }
    Ok(scripts
        .get("test")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|s| !s.trim().is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct Context(PathBuf);

    impl Context {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "devops-tool-scaffold-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn file(&self, name: &str, content: &str) {
            let path = self.0.join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }
        fn options(&self, template: ScaffoldTemplate, execute: bool) -> ScaffoldOptions {
            ScaffoldOptions {
                template,
                context: self.0.clone(),
                execute,
                binary: None,
                port: 8080,
                health_path: None,
            }
        }
    }

    impl Drop for Context {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn rust_preview_and_execute() {
        let ctx = Context::new();
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/main.rs", "fn main() {}\n");
        run(&ctx.options(ScaffoldTemplate::Rust, false)).unwrap();
        assert!(!ctx.0.join("Dockerfile").exists());
        run(&ctx.options(ScaffoldTemplate::Rust, true)).unwrap();
        let dockerfile = fs::read_to_string(ctx.0.join("Dockerfile")).unwrap();
        assert!(dockerfile.contains("cargo build --locked --release --bin hello"));
        assert!(dockerfile.contains("FROM source AS test"));
        assert!(dockerfile.contains("cargo test --locked"));
        assert!(dockerfile.contains("cp target/release/hello /out/app"));
        assert!(!ctx.0.join("scaffold.nginx.conf").exists());
        assert!(run(&ctx.options(ScaffoldTemplate::Rust, true)).is_err());
    }

    #[test]
    fn static_templates_are_locked_and_deterministic() {
        for (template, lock) in [
            (ScaffoldTemplate::NpmStatic, "package-lock.json"),
            (ScaffoldTemplate::BunStatic, "bun.lock"),
        ] {
            let ctx = Context::new();
            ctx.file(
                "package.json",
                r#"{"scripts":{"build":"vite build","test":"node --test"}}"#,
            );
            ctx.file(lock, "lock");
            run(&ctx.options(template, true)).unwrap();
            let first = fs::read_to_string(ctx.0.join("Dockerfile")).unwrap();
            assert!(first.contains("RUN npm run test") || first.contains("RUN bun run test"));
            assert!(first.contains("test -d dist"));
            assert!(ctx.0.join("scaffold.nginx.conf").is_file());
            assert!(
                fs::read_to_string(ctx.0.join("compose.yaml"))
                    .unwrap()
                    .contains("IMAGE_REF:?")
            );
            let second = Context::new();
            second.file(
                "package.json",
                r#"{"scripts":{"build":"vite build","test":"node --test"}}"#,
            );
            second.file(lock, "lock");
            run(&second.options(template, true)).unwrap();
            assert_eq!(
                first,
                fs::read_to_string(second.0.join("Dockerfile")).unwrap()
            );
        }
    }

    #[test]
    fn missing_test_target_fails_explicitly() {
        let ctx = Context::new();
        ctx.file("package.json", r#"{"scripts":{"build":"vite build"}}"#);
        ctx.file("package-lock.json", "lock");
        run(&ctx.options(ScaffoldTemplate::NpmStatic, true)).unwrap();
        assert!(
            fs::read_to_string(ctx.0.join("Dockerfile"))
                .unwrap()
                .contains("No test script in package.json; test target unavailable")
        );
    }

    #[test]
    fn rejects_ambiguity_escape_and_existing_files() {
        let ctx = Context::new();
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/main.rs", "fn main() {}\n");
        ctx.file("src/bin/other.rs", "fn main() {}\n");
        assert!(run(&ctx.options(ScaffoldTemplate::Rust, false)).is_err());
        let mut options = ctx.options(ScaffoldTemplate::Rust, false);
        options.binary = Some("other".into());
        run(&options).unwrap();
        options.context = ctx.0.join("../escape");
        assert!(run(&options).is_err());
        options.context = ctx.0.clone();
        ctx.file(".dockerignore", "keep me");
        options.execute = true;
        assert!(run(&options).is_err());
        assert_eq!(
            fs::read_to_string(ctx.0.join(".dockerignore")).unwrap(),
            "keep me"
        );
        assert!(!ctx.0.join("Dockerfile").exists());
    }

    #[test]
    fn rejects_dangling_output_symlink_when_supported() {
        let ctx = Context::new();
        ctx.file("package.json", r#"{"scripts":{"build":"vite build"}}"#);
        ctx.file("package-lock.json", "lock");
        let link = ctx.0.join("Dockerfile");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink("missing", &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file("missing", &link).is_ok();
        if linked {
            assert!(run(&ctx.options(ScaffoldTemplate::NpmStatic, true)).is_err());
            assert!(fs::symlink_metadata(link).unwrap().file_type().is_symlink());
        }
    }

    #[test]
    fn reservation_failure_removes_only_our_files() {
        let ctx = Context::new();
        ctx.file("existing", "original");
        let outputs = [("first", "one".into()), ("existing", "replacement".into())];
        assert!(write_outputs(&ctx.0, &outputs).is_err());
        assert!(!ctx.0.join("first").exists());
        assert_eq!(
            fs::read_to_string(ctx.0.join("existing")).unwrap(),
            "original"
        );
    }

    #[test]
    fn rejects_missing_lock_and_hostile_names() {
        let ctx = Context::new();
        ctx.file("package.json", r#"{"scripts":{"build":"vite build"}}"#);
        assert!(run(&ctx.options(ScaffoldTemplate::NpmStatic, false)).is_err());
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/main.rs", "fn main() {}\n");
        let mut options = ctx.options(ScaffoldTemplate::Rust, false);
        options.binary = Some("hello;rm".into());
        assert!(run(&options).is_err());
        options.binary = None;
        options.health_path = Some("/health;id".into());
        assert!(run(&options).is_err());
    }

    #[test]
    fn rejects_symlinked_context_and_input_when_supported() {
        let ctx = Context::new();
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("src/main.rs", "fn main() {}\n");
        let link = ctx.0.join("Cargo.lock");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink("Cargo.toml", &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file("Cargo.toml", &link).is_ok();
        if linked {
            assert!(run(&ctx.options(ScaffoldTemplate::Rust, false)).is_err());
        }
        let parent = Context::new();
        let path = parent.0.join("linked");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink(&ctx.0, &path).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_dir(&ctx.0, &path).is_ok();
        if linked {
            let mut options = ctx.options(ScaffoldTemplate::Rust, false);
            options.context = path;
            assert!(run(&options).is_err());
        }
    }

    #[test]
    fn nested_cargo_bins_and_ambiguity() {
        let ctx = Context::new();
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/bin/tool/main.rs", "fn main() {}\n");
        assert_eq!(rust_binary(&ctx.0, None).unwrap(), "tool");
        ctx.file("src/main.rs", "fn main() {}\n");
        assert!(rust_binary(&ctx.0, None).is_err());
        assert_eq!(rust_binary(&ctx.0, Some("tool")).unwrap(), "tool");
    }

    #[test]
    fn explicit_bin_path_and_autobins_false() {
        let ctx = Context::new();
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/main.rs", "fn main() {}\n");
        ctx.file("src/bin/other/main.rs", "fn main() {}\n");
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\nautobins=false\n[[bin]]\nname='renamed'\npath='src/main.rs'\n");
        assert_eq!(rust_binary(&ctx.0, None).unwrap(), "renamed");
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n[[bin]]\nname='renamed'\npath='src/main.rs'\n");
        assert!(rust_binary(&ctx.0, None).is_err());
        assert_eq!(rust_binary(&ctx.0, Some("renamed")).unwrap(), "renamed");
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n[[bin]]\nname='renamed'\npath='src/main.rs'\n");
        fs::remove_file(ctx.0.join("src/bin/other/main.rs")).unwrap();
        assert_eq!(rust_binary(&ctx.0, None).unwrap(), "renamed");
    }

    #[test]
    fn rejects_symlinked_discovered_bin_when_supported() {
        let ctx = Context::new();
        ctx.file("Cargo.toml", "[package]\nname='hello'\nversion='0.1.0'\n");
        ctx.file("Cargo.lock", "lock");
        ctx.file("src/main.rs", "fn main() {}\n");
        fs::create_dir_all(ctx.0.join("src/bin")).unwrap();
        let link = ctx.0.join("src/bin/other.rs");
        #[cfg(unix)]
        let linked = std::os::unix::fs::symlink("../main.rs", &link).is_ok();
        #[cfg(windows)]
        let linked = std::os::windows::fs::symlink_file("../main.rs", &link).is_ok();
        if linked {
            assert!(rust_binary(&ctx.0, None).is_err());
        }
    }
}
