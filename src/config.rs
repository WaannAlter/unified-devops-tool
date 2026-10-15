use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub schema: u32,
    pub project: Project,
    pub workloads: Vec<Workload>,
    pub postgres: Option<Postgres>,
    pub verification: Option<Verification>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Postgres {
    pub host: String,
    #[serde(default = "default_postgres_port")]
    pub port: u16,
    pub database: String,
    pub username: String,
    #[serde(default = "default_password_env")]
    pub password_env: String,
    pub sslmode: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Verification {
    pub profile: PathBuf,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Project {
    pub name: String,
    #[serde(default = "default_root")]
    pub root: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum WorkloadKind {
    Backend,
    Frontend,
}

impl WorkloadKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Backend => "backend",
            Self::Frontend => "frontend",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Engine {
    Docker,
    Podman,
}

impl Engine {
    pub fn program(self) -> &'static str {
        match self {
            Self::Docker => "docker",
            Self::Podman => "podman",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Workload {
    pub name: String,
    pub kind: WorkloadKind,
    pub engine: Engine,
    pub dockerfile: PathBuf,
    pub context: PathBuf,
    pub registry: Option<String>,
    #[serde(default = "default_platforms")]
    pub platforms: Vec<String>,
}

#[derive(Debug)]
pub struct LoadedConfig {
    pub config: Config,
    pub root: PathBuf,
}

fn default_root() -> PathBuf {
    PathBuf::from(".")
}

fn default_platforms() -> Vec<String> {
    vec!["linux/amd64".to_owned()]
}

fn default_postgres_port() -> u16 {
    5432
}

fn default_password_env() -> String {
    "PGPASSWORD".to_owned()
}

impl LoadedConfig {
    pub fn load(path: &Path) -> Result<Self> {
        let (config, root) = Self::read_inputs(path)?;
        Self::from_config(config, root)
    }

    /// Parse inputs before applying CLI overrides. Call from_config to validate them.
    pub fn read_inputs(path: &Path) -> Result<(Config, PathBuf)> {
        let config_path = fs::canonicalize(path)
            .with_context(|| format!("cannot open config {}", path.display()))?;
        let raw = fs::read_to_string(&config_path)?;
        let config: Config = toml::from_str(&raw).context("invalid devops.toml")?;
        let base = config_path
            .parent()
            .context("config has no parent directory")?;
        let root = fs::canonicalize(base.join(&config.project.root))
            .context("project root does not exist")?;
        Ok((config, root))
    }

    pub fn from_config(config: Config, root: PathBuf) -> Result<Self> {
        let root = fs::canonicalize(root).context("project root does not exist")?;
        if config.schema != 1 {
            bail!("unsupported config schema {}; expected 1", config.schema);
        }
        validate_name("project", &config.project.name)?;
        if config.workloads.is_empty() {
            bail!("at least one workload is required");
        }

        for workload in &config.workloads {
            validate_name("workload", &workload.name)?;
            if let Some(registry) = &workload.registry {
                crate::publish::validate_registry(registry)?;
            }
            if workload.platforms.len() != 1 {
                bail!(
                    "workload {} must have exactly one platform for local builds",
                    workload.name
                );
            }
            if config
                .workloads
                .iter()
                .filter(|item| item.name == workload.name)
                .count()
                > 1
            {
                bail!("duplicate workload name {}", workload.name);
            }
            contained_path(&root, &workload.context, true)?;
            contained_path(&root, &workload.dockerfile, false)?;
        }
        if let Some(postgres) = &config.postgres {
            if postgres.host.is_empty()
                || postgres.database.is_empty()
                || postgres.username.is_empty()
            {
                bail!("postgres host, database, and username must not be empty");
            }
            if !valid_env_name(&postgres.password_env) {
                bail!("postgres password_env must be a valid environment variable name");
            }
        }
        if let Some(verification) = &config.verification {
            contained_path(&root, &verification.profile, false)?;
        }
        Ok(Self { config, root })
    }

    pub fn workload(&self, name: &str) -> Result<&Workload> {
        self.config
            .workloads
            .iter()
            .find(|item| item.name == name)
            .with_context(|| format!("unknown workload {name}"))
    }

    pub fn resolve_file(&self, path: &Path) -> Result<PathBuf> {
        contained_path(&self.root, path, false)
    }

    pub fn resolve_dir(&self, path: &Path) -> Result<PathBuf> {
        contained_path(&self.root, path, true)
    }
}

pub(crate) fn contained_new_file(root: &Path, path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        bail!(
            "path {} must be relative to the project root",
            path.display()
        );
    }
    let file_name = path.file_name().context("output path must name a file")?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let resolved_parent = fs::canonicalize(root.join(parent))
        .with_context(|| format!("output directory {} does not exist", parent.display()))?;
    if !resolved_parent.starts_with(root) {
        bail!("path {} escapes the project root", path.display());
    }
    let output = resolved_parent.join(file_name);
    match fs::symlink_metadata(&output) {
        Ok(_) => bail!(
            "output already exists; refusing to overwrite {}",
            path.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(output),
        Err(error) => Err(error).context("cannot inspect output destination"),
    }
}

fn valid_env_name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'A'..=b'Z') | Some(b'_'))
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn validate_name(label: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
    if !valid {
        bail!("{label} name {value:?} must use lowercase letters, digits, and hyphens");
    }
    Ok(())
}

pub(crate) fn contained_path(root: &Path, relative: &Path, directory: bool) -> Result<PathBuf> {
    if relative.is_absolute() {
        bail!(
            "path {} must be relative to the project root",
            relative.display()
        );
    }
    let resolved = fs::canonicalize(root.join(relative))
        .with_context(|| format!("path {} does not exist", relative.display()))?;
    if !resolved.starts_with(root) {
        bail!("path {} escapes the project root", relative.display());
    }
    if directory && !resolved.is_dir() {
        bail!("path {} must be a directory", relative.display());
    }
    if !directory && !resolved.is_file() {
        bail!("path {} must be a file", relative.display());
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        assert!(validate_name("project", "demo-backend").is_ok());
        assert!(validate_name("project", "Demo Backend").is_err());
    }

    #[test]
    fn parses_known_schema() {
        let parsed: Config = toml::from_str(
            r#"
schema = 1
[project]
name = "demo"
[[workloads]]
name = "api"
kind = "backend"
engine = "docker"
dockerfile = "Dockerfile"
context = "."
"#,
        )
        .unwrap();
        assert_eq!(parsed.schema, 1);
        assert_eq!(parsed.workloads[0].engine, Engine::Docker);
    }

    #[test]
    fn validates_environment_variable_names() {
        assert!(valid_env_name("DEMO_DB_PASSWORD"));
        assert!(!valid_env_name("password; whoami"));
        assert!(!valid_env_name("lowercase"));
    }

    #[test]
    fn new_output_refuses_existing_files_without_modifying_them() {
        let root = std::env::temp_dir().join(format!(
            "devops-output-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        let root = fs::canonicalize(root).unwrap();
        let output = root.join("report.json");
        assert_eq!(
            contained_new_file(&root, Path::new("report.json")).unwrap(),
            output
        );
        fs::write(&output, b"keep me").unwrap();
        assert!(contained_new_file(&root, Path::new("report.json")).is_err());
        assert_eq!(fs::read(&output).unwrap(), b"keep me");
        fs::remove_file(output).unwrap();
        fs::remove_dir(root).unwrap();
    }

    #[test]
    fn rejects_unsafe_registry_before_execution() {
        let root = std::env::current_dir().unwrap();
        for registry in [
            "https://registry.example.test/team",
            "user:pass@registry.example.test",
        ] {
            let config: Config = toml::from_str(&format!(
                "schema = 1\n[project]\nname = \"demo\"\n[[workloads]]\nname = \"api\"\nkind = \"backend\"\nengine = \"docker\"\ndockerfile = \"Cargo.toml\"\ncontext = \".\"\nregistry = \"{registry}\"\n"
            ))
            .unwrap();
            assert!(LoadedConfig::from_config(config, root.clone()).is_err());
        }
    }
}
