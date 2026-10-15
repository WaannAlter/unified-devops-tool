//! Narrow, Development-only Kubernetes delivery through an explicit kubectl context.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::process::ProcessPlan;

#[derive(Debug, Subcommand)]
pub enum KubeCommands {
    /// Validate a JSON List locally, then optionally apply it to Development.
    Apply(ApplyOptions),
    /// Show a safe summary of Development workloads and storage.
    Status(TargetOptions),
    /// Restore one Deployment to an explicit revision.
    Rollback(RollbackOptions),
}

#[derive(Clone, Debug, Args)]
pub struct TargetOptions {
    /// Explicit kubeconfig context; the ambient context is never used.
    #[arg(long)]
    pub context: String,
    /// Development namespace, ending in -development.
    #[arg(long)]
    pub namespace: String,
}

#[derive(Debug, Args)]
pub struct ApplyOptions {
    #[command(flatten)]
    pub target: TargetOptions,
    /// UTF-8 JSON Kubernetes List containing only supported namespaced resources.
    #[arg(long)]
    pub file: PathBuf,
    #[arg(long)]
    pub execute: bool,
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub wait_timeout: u64,
}

#[derive(Debug, Args)]
pub struct RollbackOptions {
    #[command(flatten)]
    pub target: TargetOptions,
    #[arg(long)]
    pub deployment: String,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub revision: u64,
    #[arg(long)]
    pub execute: bool,
    #[arg(long, default_value_t = 180, value_parser = clap::value_parser!(u64).range(1..=600))]
    pub wait_timeout: u64,
}

pub fn run(command: &KubeCommands) -> Result<()> {
    match command {
        KubeCommands::Apply(options) => apply(options),
        KubeCommands::Status(target) => status(target),
        KubeCommands::Rollback(options) => rollback(options),
    }
}

fn validate_target(target: &TargetOptions) -> Result<()> {
    ensure!(
        !target.context.is_empty()
            && target.context.trim() == target.context
            && !target.context.chars().any(char::is_control),
        "an explicit, nonempty context without control characters is required"
    );
    ensure!(
        target.namespace.ends_with("-development") && dns_name(&target.namespace),
        "only an explicit DNS-safe -development namespace is allowed"
    );
    Ok(())
}

fn dns_name(name: &str) -> bool {
    name.len() <= 63
        && !name.is_empty()
        && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.ends_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && name
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
}

fn validate_manifest(bytes: &[u8], namespace: &str) -> Result<Vec<String>> {
    let list: Value = serde_json::from_slice(bytes).context("invalid JSON List")?;
    ensure!(
        list["kind"] == "List" && list["apiVersion"] == "v1",
        "file must be a v1 Kubernetes List"
    );
    let items = list["items"]
        .as_array()
        .context("List.items must be an array")?;
    ensure!(!items.is_empty(), "List.items cannot be empty");
    let mut deployments = Vec::new();
    for item in items {
        let kind = item["kind"].as_str().context("resource kind is required")?;
        let api = item["apiVersion"]
            .as_str()
            .context("resource apiVersion is required")?;
        ensure!(
            matches!(
                (api, kind),
                ("apps/v1", "Deployment")
                    | ("v1", "Service" | "ConfigMap" | "PersistentVolumeClaim")
                    | ("networking.k8s.io/v1", "NetworkPolicy")
            ),
            "resource kind or API version is not allowed: {kind}"
        );
        let name = item["metadata"]["name"]
            .as_str()
            .context("resource metadata.name is required")?;
        ensure!(dns_name(name), "resource name is not DNS-safe");
        ensure!(
            item["metadata"]["namespace"] == namespace,
            "resource namespace does not match target"
        );
        if kind == "ConfigMap" {
            for field in ["data", "binaryData"] {
                if let Some(data) = item[field].as_object() {
                    ensure!(
                        !data.keys().any(|key| credential_key(key)),
                        "ConfigMap has a credential-like key; provision credentials as an operator Secret"
                    );
                }
            }
        }
        if kind == "Deployment" {
            validate_deployment(item)?;
            deployments.push(name.to_owned());
        }
    }
    Ok(deployments)
}

fn credential_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    [
        "password",
        "passwd",
        "token",
        "secret",
        "private_key",
        "api_key",
    ]
    .iter()
    .any(|suffix| key == *suffix || key.ends_with(&format!("_{suffix}")))
}

fn validate_deployment(item: &Value) -> Result<()> {
    let spec = &item["spec"];
    ensure!(
        spec["replicas"].is_null() || spec["replicas"] == 1,
        "Deployment must have one replica"
    );
    let pod = &spec["template"]["spec"];
    ensure!(pod["hostNetwork"] != true, "hostNetwork is forbidden");
    if let Some(volumes) = pod["volumes"].as_array() {
        ensure!(
            !volumes.iter().any(|volume| !volume["hostPath"].is_null()),
            "hostPath is forbidden"
        );
    }
    let containers = pod["containers"]
        .as_array()
        .context("Deployment containers are required")?;
    ensure!(
        !containers.is_empty(),
        "Deployment containers cannot be empty"
    );
    let empty = Vec::new();
    for (field, entries) in [
        ("containers", containers),
        (
            "initContainers",
            pod["initContainers"].as_array().unwrap_or(&empty),
        ),
    ] {
        for container in entries {
            let image = container["image"]
                .as_str()
                .context("container image is required")?;
            ensure!(
                digest_image(image),
                "{field} image must be sha256 digest-pinned"
            );
            ensure!(
                container["securityContext"]["privileged"] != true,
                "privileged containers are forbidden"
            );
            if field == "containers" {
                ensure!(
                    container["readinessProbe"].is_object(),
                    "each container needs a readinessProbe"
                );
            }
            if let Some(env) = container["env"].as_array() {
                for variable in env {
                    if variable["name"].as_str().is_some_and(credential_key) {
                        ensure!(
                            variable["value"].is_null(),
                            "credential-like environment variable must not have an inline value"
                        );
                    }
                }
            }
        }
    }
    Ok(())
}

fn digest_image(image: &str) -> bool {
    let Some((repository, digest)) = image.rsplit_once("@sha256:") else {
        return false;
    };
    !repository.is_empty()
        && !repository.chars().any(char::is_whitespace)
        && digest.len() == 64
        && digest.bytes().all(|c| c.is_ascii_hexdigit())
}

fn kubectl(target: &TargetOptions) -> ProcessPlan {
    ProcessPlan::new("kubectl")
        .arg(format!("--context={}", target.context))
        .arg(format!("--namespace={}", target.namespace))
}

fn apply(options: &ApplyOptions) -> Result<()> {
    validate_target(&options.target)?;
    let bytes = fs::read(&options.file).context("cannot read manifest file")?;
    let deployments = validate_manifest(&bytes, &options.target.namespace)?;
    if !options.execute {
        println!(
            "{}",
            json!({"result":"validated","executed":false,"namespace":options.target.namespace,"deployments":deployments})
        );
        return Ok(());
    }
    let filename = options
        .file
        .canonicalize()
        .context("cannot resolve manifest path")?;
    checked(
        kubectl(&options.target)
            .arg("apply")
            .arg("--dry-run=server")
            .arg("-f")
            .arg(&filename),
    )?;
    checked(
        kubectl(&options.target)
            .arg("apply")
            .arg("-f")
            .arg(&filename),
    )?;
    for name in &deployments {
        checked(rollout_plan(&options.target, name, options.wait_timeout))?;
    }
    println!(
        "{}",
        json!({"result":"applied","executed":true,"namespace":options.target.namespace,"deployments":deployments})
    );
    Ok(())
}

fn rollout_plan(target: &TargetOptions, name: &str, seconds: u64) -> ProcessPlan {
    kubectl(target)
        .arg("rollout")
        .arg("status")
        .arg(format!("deployment/{name}"))
        .arg(format!("--timeout={seconds}s"))
}

fn checked(plan: ProcessPlan) -> Result<Vec<u8>> {
    let output = plan.capture()?;
    ensure!(
        output.status.success(),
        "kubectl failed with {}",
        output.status
    );
    Ok(output.stdout)
}

fn status(target: &TargetOptions) -> Result<()> {
    validate_target(target)?;
    let output = checked(
        kubectl(target)
            .arg("get")
            .arg("deployments,pods,services,pvc")
            .arg("-o=json"),
    )?;
    let list: Value = serde_json::from_slice(&output).context("invalid kubectl JSON")?;
    let items = list["items"]
        .as_array()
        .context("kubectl response has no items")?;
    let summary: Vec<Value> = items.iter().map(|item| {
        json!({"kind":item["kind"],"name":item["metadata"]["name"],"namespace":item["metadata"]["namespace"],"replicas":item["status"]["readyReplicas"],"phase":item["status"]["phase"]})
    }).collect();
    println!(
        "{}",
        json!({"namespace":target.namespace,"resources":summary})
    );
    Ok(())
}

fn rollback(options: &RollbackOptions) -> Result<()> {
    validate_target(&options.target)?;
    ensure!(
        dns_name(&options.deployment),
        "deployment name is not DNS-safe"
    );
    ensure!(options.revision > 0, "revision must be positive");
    if !options.execute {
        println!(
            "{}",
            json!({"result":"validated","executed":false,"namespace":options.target.namespace,"deployment":options.deployment,"revision":options.revision})
        );
        return Ok(());
    }
    checked(
        kubectl(&options.target)
            .arg("rollout")
            .arg("undo")
            .arg(format!("deployment/{}", options.deployment))
            .arg(format!("--to-revision={}", options.revision)),
    )?;
    checked(rollout_plan(
        &options.target,
        &options.deployment,
        options.wait_timeout,
    ))?;
    println!(
        "{}",
        json!({"result":"rolled_back","executed":true,"namespace":options.target.namespace,"deployment":options.deployment,"revision":options.revision})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> TargetOptions {
        TargetOptions {
            context: "dev-cluster".into(),
            namespace: "demo-development".into(),
        }
    }

    fn manifest() -> Value {
        json!({"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"api","namespace":"demo-development"},"spec":{"replicas":1,"template":{"spec":{"containers":[{"name":"api","image":format!("example/api@sha256:{}", "a".repeat(64)),"readinessProbe":{"httpGet":{"path":"/readyz","port":8080}}}]}}}}]})
    }

    #[test]
    fn validates_development_and_digest() {
        validate_target(&target()).unwrap();
        assert_eq!(
            validate_manifest(
                &serde_json::to_vec(&manifest()).unwrap(),
                "demo-development"
            )
            .unwrap(),
            ["api"]
        );
        for namespace in [
            "default",
            "kube-system",
            "demo-production",
            "Bad-development",
        ] {
            assert!(
                validate_target(&TargetOptions {
                    namespace: namespace.into(),
                    ..target()
                })
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_unsafe_resources() {
        for (path, value) in [
            ("kind", json!("Secret")),
            ("namespace", json!("other-development")),
            ("image", json!("example/api:latest")),
            ("privileged", json!(true)),
            ("hostNetwork", json!(true)),
            ("hostPath", json!({"path":"/"})),
        ] {
            let mut list = manifest();
            let item = &mut list["items"][0];
            match path {
                "kind" => item["kind"] = value,
                "namespace" => item["metadata"]["namespace"] = value,
                "image" => item["spec"]["template"]["spec"]["containers"][0]["image"] = value,
                "privileged" => {
                    item["spec"]["template"]["spec"]["containers"][0]["securityContext"]["privileged"] =
                        value
                }
                "hostNetwork" => item["spec"]["template"]["spec"]["hostNetwork"] = value,
                _ => {
                    item["spec"]["template"]["spec"]["volumes"] =
                        json!([{"name":"bad","hostPath":value}])
                }
            }
            assert!(
                validate_manifest(&serde_json::to_vec(&list).unwrap(), "demo-development").is_err(),
                "accepted {path}"
            );
        }
    }

    #[test]
    fn constructs_explicit_scoped_commands() {
        assert_eq!(
            kubectl(&target()).arg("get").arg("pods").args,
            [
                "--context=dev-cluster",
                "--namespace=demo-development",
                "get",
                "pods"
            ]
        );
        assert_eq!(
            rollout_plan(&target(), "api", 180).args,
            [
                "--context=dev-cluster",
                "--namespace=demo-development",
                "rollout",
                "status",
                "deployment/api",
                "--timeout=180s"
            ]
        );
    }
}
