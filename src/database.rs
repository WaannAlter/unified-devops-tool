use std::env;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::config::{LoadedConfig, Postgres, contained_new_file, contained_path};
use crate::process::ProcessPlan;

// Expand only after a real recovery drill with that client/server major.
const SUPPORTED_MAJOR: u32 = 17;

pub struct Target {
    root: PathBuf,
    postgres: Option<Postgres>,
    standalone: bool,
}

impl Target {
    pub fn from_config(loaded: LoadedConfig) -> Self {
        Self {
            root: loaded.root,
            postgres: loaded.config.postgres,
            standalone: false,
        }
    }

    pub fn standalone() -> Result<Self> {
        Ok(Self {
            root: fs::canonicalize(env::current_dir()?)?,
            postgres: None,
            standalone: true,
        })
    }

    fn connection(&self) -> Result<Postgres> {
        let postgres = match &self.postgres {
            Some(postgres) => postgres.clone(),
            None if self.standalone => {
                let port = env::var("PGPORT")
                    .ok()
                    .map(|port| port.parse::<u16>())
                    .transpose()
                    .context("PGPORT must be a numeric port")?
                    .unwrap_or(5432);
                if port == 0 {
                    bail!("PGPORT must be between 1 and 65535");
                }
                Postgres {
                    host: required_env("PGHOST")?,
                    port,
                    database: required_env("PGDATABASE")?,
                    username: required_env("PGUSER")?,
                    password_env: "PGPASSWORD".into(),
                    sslmode: env::var("PGSSLMODE").ok(),
                }
            }
            None => bail!("[postgres] is not configured"),
        };
        validate_connection(&postgres)?;
        Ok(postgres)
    }
}

fn required_env(name: &str) -> Result<String> {
    let value = env::var(name)
        .with_context(|| format!("{name} must be set for standalone database operations"))?;
    if value.is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

pub fn backup(target: &Target, output: &Path, execute: bool) -> Result<()> {
    let started = Instant::now();
    let postgres = target.connection()?;
    let output = contained_new_file(&target.root, output)?;
    let sidecar = checksum_path(&output);
    if fs::symlink_metadata(&output).is_ok() || fs::symlink_metadata(&sidecar).is_ok() {
        bail!(
            "refusing to overwrite existing backup or checksum at {}",
            output.display()
        );
    }
    let plan = connection_args(ProcessPlan::new("pg_dump").arg("--no-password"), &postgres)
        .env("PGAPPNAME", "devops-tool-backup")
        .arg("--format=custom")
        .arg("--lock-wait-timeout=30000")
        .arg("--file")
        .arg(&output)
        .arg("--dbname")
        .arg(&postgres.database);
    println!("backup\t{}", output.display());
    println!("command\t{}", plan.display());
    if !execute {
        println!("result\tplan-only (pass --execute to create backup)");
        return Ok(());
    }

    let plan = with_password(plan, &postgres)?;
    client_major("pg_restore")?;
    preflight(&postgres, "pg_dump")?;
    // Reserve the path with private permissions before pg_dump opens it.
    drop(create_private_file(&output)?);
    let result = plan.run();
    if let Err(error) = result {
        fs::remove_file(&output)
            .context("backup failed and partial archive cleanup failed; quarantine the output")?;
        return Err(error.context("PostgreSQL backup failed; partial output removed"));
    }
    let mut sidecar_created = false;
    let result = (|| -> Result<String> {
        archive_versions(&output)?;
        secure_permissions(&output)?;
        File::open(&output)?.sync_all()?;
        let digest = sha256(&output)?;
        let mut checksum = create_private_file(&sidecar)?;
        sidecar_created = true;
        writeln!(
            checksum,
            "{digest}  {}",
            output.file_name().unwrap_or_default().to_string_lossy()
        )?;
        checksum.sync_all()?;
        Ok(digest)
    })();
    let digest = match result {
        Ok(digest) => digest,
        Err(error) => {
            let archive_cleanup = fs::remove_file(&output);
            if sidecar_created {
                fs::remove_file(&sidecar).context(
                    "backup validation failed and checksum cleanup failed; quarantine the output",
                )?;
            }
            archive_cleanup.context(
                "backup validation failed and archive cleanup failed; quarantine the output",
            )?;
            return Err(error.context("backup checksum failed; incomplete files removed"));
        }
    };
    println!("sha256\t{digest}");
    println!("elapsed_ms\t{}", started.elapsed().as_millis());
    println!("result\tbackup-created-and-checksummed");
    Ok(())
}

pub fn verify_backup(target: &Target, input: &Path) -> Result<()> {
    let input = contained_path(&target.root, input, false)?;
    verify_checksum(&input)?;
    archive_versions(&input)?;
    println!("backup\t{}", input.display());
    println!("result\tchecksum-and-archive-verified");
    println!("scope\tarchive listing only; data recovery requires a successful restore drill");
    Ok(())
}

pub fn restore(
    target: &Target,
    input: &Path,
    confirmation: Option<&str>,
    target_confirmation: Option<&str>,
    execute: bool,
) -> Result<()> {
    let started = Instant::now();
    let postgres = target.connection()?;
    let identity = format!("{}:{}/{}", postgres.host, postgres.port, postgres.database);
    let input = contained_path(&target.root, input, false)?;
    let plan = connection_args(
        ProcessPlan::new("pg_restore").arg("--no-password"),
        &postgres,
    )
    .env("PGAPPNAME", "devops-tool-restore")
    .arg("--format=custom")
    .arg("--clean")
    .arg("--if-exists")
    .arg("--single-transaction")
    .arg("--no-owner")
    .arg("--no-privileges")
    .arg("--dbname")
    .arg(&postgres.database)
    .arg(&input);
    println!("database\t{}", postgres.database);
    println!("target\t{identity}");
    println!("backup\t{}", input.display());
    println!("command\t{}", plan.display());
    if !execute {
        println!(
            "result\tplan-only (restore requires --execute, --confirm-database and --confirm-target)"
        );
        return Ok(());
    }
    if confirmation != Some(postgres.database.as_str()) {
        bail!(
            "restore confirmation must exactly match database {}",
            postgres.database
        );
    }
    ensure!(
        target_confirmation == Some(identity.as_str()),
        "restore --confirm-target must exactly match {identity}"
    );
    verify_checksum(&input)?;
    archive_versions(&input)?;
    let plan = with_password(plan, &postgres)?;
    preflight(&postgres, "pg_restore")?;
    plan.run().context(
        "restore failed; inspect target before retry (single transaction, no automatic retry)",
    )?;
    println!("elapsed_ms\t{}", started.elapsed().as_millis());
    println!("result\trestore-completed");
    Ok(())
}

fn create_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    // Windows ACLs are set while the reserved file is still empty.
    if let Err(error) = secure_permissions(path) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(file)
}

fn connection_args(plan: ProcessPlan, postgres: &Postgres) -> ProcessPlan {
    let plan = plan
        .env("LC_ALL", "C")
        .env("PGCONNECT_TIMEOUT", "10")
        .arg("--host")
        .arg(&postgres.host)
        .arg("--port")
        .arg(postgres.port.to_string())
        .arg("--username")
        .arg(&postgres.username);
    match &postgres.sslmode {
        Some(sslmode) => plan.env("PGSSLMODE", sslmode),
        None => plan,
    }
}

fn validate_connection(postgres: &Postgres) -> Result<()> {
    // libpq accepts connection strings in --dbname, overriding explicit host/user.
    // Keep this API a literal single-target interface, never a URI/option parser.
    for (label, value) in [
        ("host", &postgres.host),
        ("database", &postgres.database),
        ("username", &postgres.username),
    ] {
        ensure!(
            !value.is_empty()
                && !value.starts_with('-')
                && !value.contains(['=', ',', '|'])
                && !value.contains("://")
                && !value.chars().any(char::is_control),
            "PostgreSQL {label} must be a literal single-target value, not a connection string"
        );
    }
    ensure!(postgres.port != 0, "PostgreSQL port must be nonzero");
    for name in ["PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"] {
        ensure!(
            env::var_os(name).is_none_or(|value| value.is_empty()),
            "unset {name}: indirect connection overrides are not supported"
        );
    }
    if let Some(mode) = &postgres.sslmode {
        ensure!(
            [
                "disable",
                "allow",
                "prefer",
                "require",
                "verify-ca",
                "verify-full"
            ]
            .contains(&mode.as_str()),
            "unsupported PostgreSQL sslmode"
        );
    }
    Ok(())
}

fn version_major(version: &str) -> Result<u32> {
    version
        .split('.')
        .next()
        .context("missing PostgreSQL version")?
        .parse()
        .context("invalid PostgreSQL version")
}

fn supported(major: u32) -> Result<()> {
    ensure!(
        major == SUPPORTED_MAJOR,
        "unsupported PostgreSQL major {major}; validated recovery requires major {SUPPORTED_MAJOR} clients, source and target (no automatic download or upgrade)"
    );
    Ok(())
}

fn client_major(program: &str) -> Result<u32> {
    let output = ProcessPlan::new(program)
        .env("LC_ALL", "C")
        .arg("--version")
        .output()?;
    let text = String::from_utf8(output)?;
    let version = text
        .split("(PostgreSQL) ")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .context("cannot identify PostgreSQL client version")?;
    let major = version_major(version)?;
    supported(major)?;
    Ok(major)
}

fn preflight(postgres: &Postgres, program: &str) -> Result<()> {
    let client = client_major(program)?;
    client_major("psql")?;
    let plan = connection_args(ProcessPlan::new("psql"), postgres)
        .env("PGAPPNAME", "devops-tool-preflight")
        .arg("--no-psqlrc")
        .arg("--no-password")
        .arg("--tuples-only")
        .arg("--no-align")
        .arg("--set=ON_ERROR_STOP=1")
        .arg("--dbname")
        .arg(&postgres.database)
        .arg("--command")
        .arg("SELECT current_setting('server_version_num'), current_database(), current_user");
    let output = with_password(plan, postgres)?.output().context(
        "PostgreSQL target preflight failed (connection or authentication); no data changed",
    )?;
    let text = String::from_utf8(output)?;
    let fields: Vec<_> = text.trim().split('|').collect();
    ensure!(
        fields.len() == 3,
        "unexpected PostgreSQL target identity response"
    );
    let server = fields[0].parse::<u32>().context("invalid server version")? / 10000;
    supported(server)?;
    ensure!(
        server == client && fields[1] == postgres.database && fields[2] == postgres.username,
        "PostgreSQL connected target/user/version does not match requested target"
    );
    println!("postgres_major\t{server}");
    Ok(())
}

fn archive_versions(input: &Path) -> Result<()> {
    client_major("pg_restore")?;
    let output = ProcessPlan::new("pg_restore")
        .env("LC_ALL", "C")
        .arg("--format=custom")
        .arg("--list")
        .arg(input)
        .output()
        .context("backup is not a readable PostgreSQL custom archive")?;
    let listing = String::from_utf8(output)?;
    for marker in [
        "Dumped from database version: ",
        "Dumped by pg_dump version: ",
    ] {
        let version = listing
            .lines()
            .find_map(|line| line.split_once(marker).map(|(_, value)| value))
            .and_then(|value| value.split_whitespace().next())
            .context("archive is missing PostgreSQL version metadata")?;
        supported(version_major(version)?)?;
    }
    Ok(())
}

fn with_password(plan: ProcessPlan, postgres: &Postgres) -> Result<ProcessPlan> {
    let password = env::var_os(&postgres.password_env).with_context(|| {
        format!(
            "required environment variable {} is not set",
            postgres.password_env
        )
    })?;
    Ok(plan.env("PGPASSWORD", password))
}

fn checksum_path(path: &Path) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(".sha256");
    PathBuf::from(value)
}

fn verify_checksum(path: &Path) -> Result<()> {
    let sidecar = checksum_path(path);
    let expected = fs::read_to_string(&sidecar)
        .with_context(|| format!("missing checksum file {}", sidecar.display()))?
        .split_whitespace()
        .next()
        .context("checksum file is empty")?
        .to_ascii_lowercase();
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("checksum file contains an invalid SHA-256 digest");
    }
    let actual = sha256(path)?;
    if actual != expected {
        bail!("backup checksum mismatch");
    }
    Ok(())
}

fn sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

#[cfg(unix)]
fn secure_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(windows)]
fn secure_permissions(path: &Path) -> Result<()> {
    // Replace (rather than amend) the DACL, including any explicit default ACEs.
    // The path is an environment value, never interpolated into PowerShell code.
    ProcessPlan::new("powershell.exe")
        .env("DEVOPS_TOOL_BACKUP_ACL_PATH", path.as_os_str())
        .arg("-NoProfile")
        .arg("-NonInteractive")
        .arg("-Command")
        .arg(r#"
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.FileSecurity
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'Allow'))
[System.IO.File]::SetAccessControl($env:DEVOPS_TOOL_BACKUP_ACL_PATH, $acl)
$actual = [System.IO.File]::GetAccessControl($env:DEVOPS_TOOL_BACKUP_ACL_PATH)
$rules = $actual.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
if (-not $actual.AreAccessRulesProtected -or $rules.Count -ne 1 -or
    $rules[0].IdentityReference.Value -ne $sid.Value -or $rules[0].IsInherited -or
    $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') {
    throw 'backup DACL verification failed'
}
"#)
        .output()
        .context("cannot set and verify a current-user-only backup ACL")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_sidecar_does_not_replace_extension() {
        assert_eq!(
            checksum_path(Path::new("backup.dump")),
            PathBuf::from("backup.dump.sha256")
        );
    }

    #[test]
    fn recovery_version_policy_fails_closed() {
        assert_eq!(version_major("17.11").unwrap(), 17);
        assert!(supported(17).is_ok());
        for major in [0, 9, 14, 16, 18, 19] {
            assert!(supported(major).is_err());
        }
        assert!(version_major("unknown").is_err());
    }

    #[test]
    fn literal_connection_rejects_target_overrides_without_echoing_values() {
        for invalid in [
            "host=other password=do-not-print",
            "postgresql://user:do-not-print@other/db",
            "--help",
            "source\nother",
        ] {
            let postgres = Postgres {
                host: "localhost".into(),
                port: 5432,
                database: invalid.into(),
                username: "fixture".into(),
                password_env: "PGPASSWORD".into(),
                sslmode: None,
            };
            let error = validate_connection(&postgres).unwrap_err().to_string();
            assert!(error.contains("literal"));
            assert!(!error.contains("do-not-print"));
        }
    }

    #[test]
    fn private_archive_reservation_refuses_overwrite() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            env::temp_dir().join(format!("devops-tool-backup-{}-{nonce}", std::process::id()));
        let mut file = create_private_file(&path).unwrap();
        file.write_all(b"synthetic backup").unwrap();
        assert!(create_private_file(&path).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        }
        #[cfg(windows)]
        {
            ProcessPlan::new("icacls.exe")
                .arg(&path)
                .arg("/grant")
                .arg("*S-1-1-0:(R)")
                .output()
                .unwrap();
            // Deliberately broaden this synthetic file, then require exact repair.
            secure_permissions(&path).unwrap();
            let acl = ProcessPlan::new("icacls.exe").arg(&path).output().unwrap();
            assert!(!String::from_utf8_lossy(&acl).contains("(I)"));
        }
        drop(file);
        assert_eq!(fs::read(&path).unwrap(), b"synthetic backup");
        fs::remove_file(path).unwrap();
    }
}
