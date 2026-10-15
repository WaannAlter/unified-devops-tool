use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;

use crate::config::{Config, Engine, LoadedConfig, Project, Workload, WorkloadKind};

#[derive(Debug, Default, PartialEq, Args)]
pub struct BuildOptions {
    #[arg(long)]
    pub context: Option<PathBuf>,
    #[arg(long)]
    pub dockerfile: Option<PathBuf>,
    #[arg(long)]
    pub project_name: Option<String>,
    #[arg(long, value_enum)]
    pub kind: Option<WorkloadKind>,
    #[arg(long, value_enum)]
    pub engine: Option<Engine>,
    #[arg(long)]
    pub platform: Option<String>,
    /// Registry host[:port][/namespace]; credentials stay in the engine configuration.
    #[arg(long)]
    pub registry: Option<String>,
}

fn selected_config(config_path: Option<&Path>) -> Result<Option<PathBuf>> {
    match config_path {
        Some(path) => Ok(Some(path.to_path_buf())),
        None => {
            let candidate = PathBuf::from("devops.toml");
            Ok(candidate.try_exists()?.then_some(candidate))
        }
    }
}

/// Keep bare `validate` compatible with multi-workload configuration files.
pub fn validate(
    config_path: Option<&Path>,
    requested_workload: Option<&str>,
    options: &BuildOptions,
) -> Result<()> {
    let configured = selected_config(config_path)?;
    if let Some(path) = &configured
        && requested_workload.is_none()
        && options == &BuildOptions::default()
    {
        LoadedConfig::load(path)?;
    } else {
        load(config_path, requested_workload, options)?;
    }
    println!(
        "config\t{}",
        configured.as_deref().map_or_else(
            || "none (flags/defaults)".into(),
            |path| path.display().to_string()
        )
    );
    println!("result\tvalid");
    Ok(())
}

pub fn load(
    config_path: Option<&Path>,
    requested_workload: Option<&str>,
    options: &BuildOptions,
) -> Result<(LoadedConfig, String, Option<PathBuf>)> {
    let cwd = std::env::current_dir().context("cannot determine current directory")?;
    load_at(&cwd, config_path, requested_workload, options)
}

fn load_at(
    cwd: &Path,
    config_path: Option<&Path>,
    requested_workload: Option<&str>,
    options: &BuildOptions,
) -> Result<(LoadedConfig, String, Option<PathBuf>)> {
    let configured = match config_path {
        Some(path) => Some(cwd.join(path)),
        None => {
            let candidate = cwd.join("devops.toml");
            candidate.try_exists()?.then_some(candidate)
        }
    };
    let (loaded, name) = match &configured {
        Some(path) => load_configured(path, requested_workload, options),
        None => load_defaults(cwd, requested_workload, options),
    }?;
    // Return the actual selected config with its loaded inputs; publication must
    // not rediscover a different file between selection and source inspection.
    Ok((loaded, name, configured))
}

fn load_configured(
    path: &Path,
    requested_workload: Option<&str>,
    options: &BuildOptions,
) -> Result<(LoadedConfig, String)> {
    let (mut config, root) = LoadedConfig::read_inputs(path)?;
    if let Some(name) = &options.project_name {
        config.project.name = name.clone();
    }
    let selected = match requested_workload {
        Some(name) => name,
        None if config.workloads.len() == 1 => &config.workloads[0].name,
        None => bail!("multiple workloads are configured; pass --workload"),
    }
    .to_owned();
    let workload = config
        .workloads
        .iter_mut()
        .find(|workload| workload.name == selected)
        .with_context(|| format!("unknown workload {selected}"))?;
    apply_overrides(workload, options);
    let loaded = LoadedConfig::from_config(config, root)?;
    Ok((loaded, selected))
}

fn load_defaults(
    cwd: &Path,
    requested_workload: Option<&str>,
    options: &BuildOptions,
) -> Result<(LoadedConfig, String)> {
    let root = fs::canonicalize(cwd)
        .with_context(|| format!("cannot open project root {}", cwd.display()))?;
    let name = options
        .project_name
        .clone()
        .unwrap_or_else(|| default_project_name(&root));
    if name.is_empty() {
        bail!("cannot derive a project name; pass --project-name");
    }
    let workload_name = requested_workload.unwrap_or("app").to_owned();
    let context = options
        .context
        .clone()
        .unwrap_or_else(|| PathBuf::from("."));
    let dockerfile = options
        .dockerfile
        .clone()
        .unwrap_or_else(|| context.join("Dockerfile"));
    if !root.join(&dockerfile).is_file() {
        bail!(
            "Dockerfile {} does not exist; pass --dockerfile",
            dockerfile.display()
        );
    }
    let workload = Workload {
        name: workload_name.clone(),
        kind: options.kind.unwrap_or(WorkloadKind::Backend),
        engine: options.engine.unwrap_or(Engine::Docker),
        dockerfile,
        context,
        registry: options.registry.clone(),
        platforms: vec![
            options
                .platform
                .clone()
                .unwrap_or_else(|| "linux/amd64".into()),
        ],
    };
    let config = Config {
        schema: 1,
        project: Project {
            name,
            root: PathBuf::from("."),
        },
        workloads: vec![workload],
        postgres: None,
        verification: None,
    };
    Ok((LoadedConfig::from_config(config, root)?, workload_name))
}

fn apply_overrides(workload: &mut Workload, options: &BuildOptions) {
    if let Some(context) = &options.context {
        workload.context = context.clone();
    }
    if let Some(dockerfile) = &options.dockerfile {
        workload.dockerfile = dockerfile.clone();
    }
    if let Some(kind) = options.kind {
        workload.kind = kind;
    }
    if let Some(engine) = options.engine {
        workload.engine = engine;
    }
    if let Some(platform) = &options.platform {
        workload.platforms = vec![platform.clone()];
    }
    if let Some(registry) = &options.registry {
        workload.registry = Some(registry.clone());
    }
}

fn default_project_name(root: &Path) -> String {
    root.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() {
                character.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT: AtomicUsize = AtomicUsize::new(0);

    struct TempDir(PathBuf);
    impl TempDir {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "onboarding {name} {} {} {}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn config(workloads: &str) -> String {
        format!("schema = 1\n[project]\nname = \"demo\"\nroot = \".\"\n{workloads}")
    }

    #[test]
    fn defaults_work_in_a_spaced_directory() {
        let temp = TempDir::new("spaced root");
        fs::write(temp.0.join("Dockerfile"), "FROM scratch\n").unwrap();
        let (loaded, name, configured) =
            load_at(&temp.0, None, None, &BuildOptions::default()).unwrap();
        assert_eq!(name, "app");
        assert!(configured.is_none());
        assert_eq!(loaded.config.workloads[0].context, PathBuf::from("."));
        assert_eq!(
            loaded.config.workloads[0].dockerfile,
            PathBuf::from(".").join("Dockerfile")
        );
    }

    #[test]
    fn config_overrides_preserve_dockerfile_unless_explicit() {
        let temp = TempDir::new("override");
        fs::create_dir_all(temp.0.join("api")).unwrap();
        fs::create_dir_all(temp.0.join("other")).unwrap();
        fs::write(temp.0.join("custom.Dockerfile"), "FROM scratch\n").unwrap();
        let path = temp.0.join("devops.toml");
        fs::write(&path, config("[[workloads]]\nname = \"api\"\nkind = \"backend\"\nengine = \"docker\"\ndockerfile = \"custom.Dockerfile\"\ncontext = \"api\"\n")).unwrap();
        let options = BuildOptions {
            context: Some(PathBuf::from("other")),
            project_name: Some("overridden-project".into()),
            registry: Some("localhost:5000/team".into()),
            ..Default::default()
        };
        let (loaded, _, configured) = load_at(&temp.0, Some(&path), None, &options).unwrap();
        assert_eq!(configured.as_deref(), Some(path.as_path()));
        assert_eq!(loaded.config.project.name, "overridden-project");
        assert_eq!(
            loaded.config.workloads[0].registry.as_deref(),
            Some("localhost:5000/team")
        );
        assert_eq!(
            loaded.config.workloads[0].dockerfile,
            PathBuf::from("custom.Dockerfile")
        );
    }

    #[test]
    fn requires_workload_when_config_is_ambiguous() {
        let temp = TempDir::new("ambiguous");
        fs::write(temp.0.join("Dockerfile"), "FROM scratch\n").unwrap();
        let path = temp.0.join("devops.toml");
        fs::write(&path, config("[[workloads]]\nname = \"one\"\nkind = \"backend\"\nengine = \"docker\"\ndockerfile = \"Dockerfile\"\ncontext = \".\"\n[[workloads]]\nname = \"two\"\nkind = \"backend\"\nengine = \"docker\"\ndockerfile = \"Dockerfile\"\ncontext = \".\"\n")).unwrap();
        assert!(load_at(&temp.0, Some(&path), None, &BuildOptions::default()).is_err());
        // Bare validate must continue to validate every configured workload.
        assert!(validate(Some(&path), None, &BuildOptions::default()).is_ok());
    }

    #[test]
    fn explicit_missing_config_does_not_fall_back() {
        let temp = TempDir::new("missing");
        fs::write(temp.0.join("Dockerfile"), "FROM scratch\n").unwrap();
        assert!(
            load_at(
                &temp.0,
                Some(&temp.0.join("missing.toml")),
                None,
                &BuildOptions::default()
            )
            .is_err()
        );
        fs::create_dir(temp.0.join("devops.toml")).unwrap();
        assert!(load_at(&temp.0, None, None, &BuildOptions::default()).is_err());
    }

    #[test]
    fn defaults_reject_an_escaping_context() {
        let temp = TempDir::new("escape");
        fs::write(temp.0.join("Dockerfile"), "FROM scratch\n").unwrap();
        let options = BuildOptions {
            context: Some(PathBuf::from("..")),
            dockerfile: Some(PathBuf::from("Dockerfile")),
            ..Default::default()
        };
        assert!(load_at(&temp.0, None, None, &options).is_err());
    }
}
