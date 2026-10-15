#!/usr/bin/env python3
"""Publish regression harness with temporary Git state and mock Docker/Trivy."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tarfile

DIGEST = "sha256:" + "a" * 64
MOVED = "sha256:" + "b" * 64
WINDOWS_LAUNCHER = None

LAUNCHER = r'''use std::{env, process::{self, Command}};
fn main() {
    let script = env::current_exe().unwrap().with_extension("py");
    let status = Command::new(env::var_os("MOCK_PYTHON").unwrap())
        .arg(script).args(env::args_os().skip(1)).status().unwrap();
    process::exit(status.code().unwrap_or(1));
}
'''

PRIVATE_EVIDENCE_ACL = r'''
$ErrorActionPreference = 'Stop'
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$acl = New-Object System.Security.AccessControl.DirectorySecurity
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow'))
[System.IO.Directory]::SetAccessControl($env:MOCK_EVIDENCE_DIR, $acl)
'''

DOCKER = r'''#!/usr/bin/env python3
import io, json, os, sys, tarfile
p=os.environ["MOCK_STATE"]
s=json.load(open(p))
def save(): json.dump(s,open(p,"w"))
a=sys.argv[1:]
if a[:3] == ["buildx","imagetools","inspect"]:
 r=a[3]
 if s.get("lookup_error"):
  print(s["lookup_error"],file=sys.stderr); sys.exit(1)
 d=s["refs"].get(r) or (r.rsplit("@",1)[1] if "@sha256:" in r else None)
 if not d: print("ERROR: %s: not found"%r,file=sys.stderr); sys.exit(1)
 if "--raw" in a: print(json.dumps({"manifests":[{"digest":d,"platform":{"os":"linux","architecture":"amd64"}}]}))
 elif "--format" in a:
  f=a[a.index("--format")+1]
  print(json.dumps({"spdxVersion":"SPDX-2.3"} if "SBOM" in f else {"buildType":"mock"} if "Provenance" in f else {"digest":d}))
 else: print(json.dumps({"digest":d}))
elif a[:2] == ["buildx","build"]:
 tag=a[a.index("--tag")+1]; meta=a[a.index("--metadata-file")+1]
 if a[a.index("--file")+1] != "Dockerfile": print("Dockerfile must be context-relative",file=sys.stderr); sys.exit(2)
 names=tarfile.open(fileobj=io.BytesIO(sys.stdin.buffer.read())).getnames()
 if "Dockerfile" not in names or "message" not in names or "devops.toml" in names: print("wrong committed context archive",file=sys.stderr); sys.exit(2)
 if s.get("expected_build_arg") and s["expected_build_arg"] not in a: print("missing expected build arg",file=sys.stderr); sys.exit(2)
 s["builds"]=s.get("builds",0)+1; s["refs"][tag]=("sha256:"+"b"*64) if s.get("move_candidate") else "sha256:"+"a"*64
 if s.get("fail_after_push"):
  print("ERROR: synthetic build failure",file=sys.stderr)
  print("ERROR: API_TOKEN=do-not-print",file=sys.stderr)
  print("FATAL abcdefghijklmnopqrstuvwxyz012345",file=sys.stderr)
  print("::warning::injected",file=sys.stderr)
  save(); sys.exit(1)
 json.dump({"containerimage.digest":"sha256:"+"a"*64},open(meta,"w"))
 save()
 if s.get("fail_after_metadata"): sys.exit(1)
elif a[:1] == ["pull"]:
 s.setdefault("local_images",[]).append(a[1]); save(); print("mock pull progress")
elif a[:2] == ["image","inspect"]:
 print(json.dumps([{"Config":{"Labels":{"org.opencontainers.image.revision":os.environ["MOCK_REV"],"org.opencontainers.image.source-component":"backend"}}}]))
elif a[:3] == ["buildx","imagetools","create"]:
 print("mock promotion progress")
 tag=a[a.index("--tag")+1]; canonical=a[-1]; s["refs"][tag]=canonical.rsplit("@",1)[1]; save()
 if s.get("fail_after_promote"): sys.exit(1)
else: print("unexpected docker: "+repr(a),file=sys.stderr); sys.exit(2)
'''

TRIVY = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
p=os.environ["MOCK_STATE"]; s=json.load(open(p)); a=sys.argv[1:]
if a[:1] == ["--version"]: print(json.dumps({"Version":"mock","VulnerabilityDB":{"UpdatedAt":"2026-01-01T00:00:00Z"}}))
elif a[:1] == ["image"]:
 if any(k.upper().startswith('TRIVY_') for k in os.environ): print('uncontrolled scanner environment',file=sys.stderr); sys.exit(2)
 for flag, fallback in (('--config','trivy.yaml'), ('--ignorefile','.trivyignore'), ('--secret-config','trivy-secret.yaml')):
  if flag not in a or a[a.index(flag)+1] != '': print('unsafe scanner config',file=sys.stderr); sys.exit(2)
  if Path(fallback).exists(): print('empty flag loaded '+fallback+' from scanner cwd',file=sys.stderr); sys.exit(2)
 secret=a[a.index('--scanners')+1]=='secret'
 if s.get("require_local_artifact") and a[-1] not in s.get("local_images",[]): print("local artifact was pruned",file=sys.stderr); sys.exit(2)
 if not secret and s.get("expected_trivy_args") and not all(arg in a for arg in s["expected_trivy_args"]): print("missing expected Trivy args",file=sys.stderr); sys.exit(2)
 if secret:
  if a[a.index('--severity')+1] != 'UNKNOWN,LOW,MEDIUM,HIGH,CRITICAL' or '--pkg-types' in a or '--ignore-unfixed' in a: sys.exit(2)
  print(json.dumps({'ArtifactName':a[-1], 'Results':[{'Target':'file', 'Secrets':[{'Severity':'LOW','Match':'do-not-print'}] if s.get('secret_finding') else []}]}))
  sys.exit(1 if s.get('secret_finding') else 0)
 report={"ArtifactName":"other" if s.get("bad_artifact") else a[-1],"Results":[{"Target":"mock","Vulnerabilities":[{"Severity":"HIGH","VulnerabilityID":"CVE-2026-12345","Description":"password=do-not-print","PkgName":"::warning::injected"},{"Severity":"CRITICAL","VulnerabilityID":"CVE-2026-12345::error::injected"}] if s.get("high_finding") else []}]}; print(json.dumps(report))
 if s.get("high_finding"): sys.exit(1)
 if s.get("scan_fail_once"):
  print("FATAL synthetic scan failure",file=sys.stderr)
  print("FATAL password=do-not-print",file=sys.stderr)
  s["scan_fail_once"]=False; json.dump(s,open(p,"w")); sys.exit(1)
else: sys.exit(2)
'''

def cmd(args, cwd, env, ok=True):
    result = subprocess.run(args, cwd=cwd, env=env, text=True, capture_output=True, timeout=60)
    if ok and result.returncode:
        raise AssertionError("command failed\n%s\n%s" % (result.stdout, result.stderr))
    if not ok and not result.returncode:
        raise AssertionError("command unexpectedly succeeded")
    return result

def fixture(base, binary, configured=True):
    repo = base / "project fixture"; repo.mkdir(parents=True); (repo / "api").mkdir()
    (repo / "api" / "Dockerfile").write_text("FROM scratch\n")
    (repo / "api" / "message").write_text("committed payload\n")
    (repo / "devops.toml").write_text('''schema = 1
[project]
name = "demo"
root = "."
[[workloads]]
name = "api"
kind = "backend"
engine = "docker"
dockerfile = "api/Dockerfile"
context = "api"
registry = "localhost:5000"
platforms = ["linux/amd64"]
''')
    if not configured:
        (repo / "devops.toml").unlink()
    # Identical trees at distinct paths catch under-specified retry identities.
    (repo / "copy api").mkdir()
    for name in ("Dockerfile", "message"):
        (repo / "copy api" / name).write_bytes((repo / "api" / name).read_bytes())
    cmd(["git","init"], repo, os.environ.copy()); cmd(["git","config","user.email","test@example.invalid"], repo, os.environ.copy()); cmd(["git","config","user.name","Test"], repo, os.environ.copy())
    cmd(["git","add","."], repo, os.environ.copy()); cmd(["git","commit","-m","fixture"], repo, os.environ.copy())
    rev=cmd(["git","rev-parse","HEAD"],repo,os.environ.copy()).stdout.strip()
    bindir=base/"mock-bin"; bindir.mkdir()
    for name, body in (("docker",DOCKER),("trivy",TRIVY)):
        path=bindir/(name+('.py' if os.name == 'nt' else ''))
        path.write_text(body)
        if os.name == 'nt': shutil.copy2(WINDOWS_LAUNCHER,bindir/(name+'.exe'))
        else: path.chmod(0o755)
    state=base/"state.json"; state.write_text(json.dumps({"refs":{},"builds":0}))
    evidence=base/"evidence"; evidence.mkdir()
    if os.name == 'nt':
        acl_env=os.environ.copy(); acl_env['MOCK_EVIDENCE_DIR']=str(evidence)
        cmd(['powershell.exe','-NoProfile','-NonInteractive','-Command',PRIVATE_EVIDENCE_ACL],base,acl_env)
    env=os.environ.copy(); env.update({"PATH":str(bindir)+os.pathsep+env["PATH"],"MOCK_STATE":str(state),"MOCK_REV":rev})
    if os.name == 'nt': env['MOCK_PYTHON']=sys.executable
    return repo, rev, evidence, state, env

def publish(binary, repo, rev, evidence, env, execute=True, expect=True, extra=()):
    args=[str(binary),"publish","--workload","api","--commit",rev,"--evidence-dir",str(evidence)]
    if (repo / "devops.toml").exists() and '--config' not in extra:
        args += ['--config', 'devops.toml']
    elif not (repo / "devops.toml").exists():
        args += ["--context", "api", "--project-name", "demo", "--registry", "localhost:5000"]
    args += list(extra)
    if execute: args.append("--execute")
    return cmd(args,repo,env,expect)

def state(path): return json.loads(path.read_text())
def set_state(path, **values): data=state(path); data.update(values); path.write_text(json.dumps(data))
def evidence_dir(root, rev):
    target="localhost:5000/demo/api:"+rev
    return root / hashlib.sha256(target.encode()).hexdigest()

def test_plan(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary); result=publish(binary,repo,rev,evidence,env,False)
    assert json.loads(result.stdout)["result"] == "plan-only" and state(statefile)["builds"] == 0 and not list(evidence.iterdir())

def test_success_retry(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary)
    first=publish(binary,repo,rev,evidence,env)
    retry=publish(binary,repo,rev,evidence,env)
    assert json.loads(first.stdout)["result"] == json.loads(retry.stdout)["result"] == "published"
    assert "mock pull progress" in first.stderr and "mock promotion progress" in first.stderr
    assert state(statefile)["builds"] == 1

def test_scan_retry(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary); set_state(statefile,scan_fail_once=True)
    env['GITHUB_ACTIONS']='true'
    failed=publish(binary,repo,rev,evidence,env,True,False)
    assert 'failure output withheld' in failed.stderr
    assert 'FATAL synthetic scan failure' not in failed.stderr
    assert 'do-not-print' not in failed.stderr
    assert '::stop-commands::' not in failed.stderr
    assert not failed.stdout
    publish(binary,repo,rev,evidence,env)
    assert state(statefile)["builds"] == 1

def test_interrupted_build(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary); set_state(statefile,fail_after_push=True)
    env['GITHUB_ACTIONS']='true'
    failed=publish(binary,repo,rev,evidence,env,True,False)
    assert 'failure output withheld' in failed.stderr
    assert 'ERROR: synthetic build failure' not in failed.stderr
    assert 'do-not-print' not in failed.stderr and '::warning::injected' not in failed.stderr
    assert 'abcdefghijklmnopqrstuvwxyz012345' not in failed.stderr
    assert '::stop-commands::' not in failed.stderr
    assert not failed.stdout
    set_state(statefile,fail_after_push=False)
    publish(binary,repo,rev,evidence,env,True,False); assert state(statefile)["builds"] == 1

def test_build_metadata_without_success_marker(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary); set_state(statefile,fail_after_metadata=True)
    publish(binary,repo,rev,evidence,env,True,False)
    directory=evidence_dir(evidence,rev)
    assert (directory/'build-metadata.json').exists() and not (directory/'build-succeeded.json').exists()
    set_state(statefile,fail_after_metadata=False)
    result=publish(binary,repo,rev,evidence,env,True,False)
    assert 'recorded successful Buildx exit' in result.stderr
    assert state(statefile)['builds'] == 1
    assert 'localhost:5000/demo/api:'+rev not in state(statefile)['refs']

def test_lookup_errors(binary, base):
    for index, error in enumerate(("unauthorized: manifest unknown", "connection refused")):
        repo, rev, evidence, statefile, env=fixture(base/str(index),binary); set_state(statefile,lookup_error=error)
        publish(binary,repo,rev,evidence,env,True,False); assert state(statefile)["builds"] == 0

def test_conflicts_and_move(binary, base):
    for kind in ("target", "candidate"):
        repo, rev, evidence, statefile, env=fixture(base/kind,binary); ref="localhost:5000/demo/api:"+(rev if kind == "target" else "candidate-"+rev)
        set_state(statefile,refs={ref:DIGEST}); publish(binary,repo,rev,evidence,env,True,False); assert state(statefile)["builds"] == 0
    repo, rev, evidence, statefile, env=fixture(base/"moved",binary); set_state(statefile,move_candidate=True)
    publish(binary,repo,rev,evidence,env,True,False); assert state(statefile)["builds"] == 1

def test_promote_and_tamper(binary, base):
    repo, rev, evidence, statefile, env=fixture(base/"promote",binary); set_state(statefile,fail_after_promote=True)
    publish(binary,repo,rev,evidence,env,True,False); set_state(statefile,fail_after_promote=False); publish(binary,repo,rev,evidence,env); assert state(statefile)["builds"] == 1
    repo, rev, evidence, statefile, env=fixture(base/"tamper",binary); publish(binary,repo,rev,evidence,env)
    (evidence_dir(evidence,rev)/"scan.json").write_text("tampered")
    publish(binary,repo,rev,evidence,env,True,False)

def test_scan_content_gates(binary, base):
    for key in ("bad_artifact", "high_finding"):
        repo, rev, evidence, statefile, env=fixture(base/key,binary); set_state(statefile, **{key: True})
        failed=publish(binary,repo,rev,evidence,env,True,False)
        if key == 'high_finding':
            assert '2 HIGH/CRITICAL finding(s)' in failed.stderr
            assert 'CVE-2026-12345 (HIGH)' in failed.stderr
            assert 'do-not-print' not in failed.stderr and '::warning::injected' not in failed.stderr
            assert 'CVE-2026-12345::error::injected' not in failed.stderr
            assert not failed.stdout
        assert "localhost:5000/demo/api:"+rev not in state(statefile)["refs"]


def test_no_config(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary,configured=False)
    plan=json.loads(publish(binary,repo,rev,evidence,env,False).stdout)
    inputs=plan['inputs']
    assert inputs['config_path'] is None and inputs['config_sha256'] is None
    assert inputs['context'] == 'api' and inputs['dockerfile'] == 'api/Dockerfile'
    assert inputs['engine'] == 'docker' and inputs['schema'] == 4
    publish(binary,repo,rev,evidence,env)
    publish(binary,repo,rev,evidence,env)
    sealed=json.loads((evidence_dir(evidence,rev)/'inputs.json').read_text())
    assert sealed == inputs and state(statefile)['builds'] == 1
    assert not (repo/'devops.toml').exists()


def test_effective_inputs_retry(binary, base):
    for configured in (True, False):
        repo, rev, evidence, statefile, env=fixture(base/str(configured),binary,configured)
        set_state(statefile,scan_fail_once=True)
        publish(binary,repo,rev,evidence,env,expect=False)
        original=state(statefile)
        # Same source SHA and identical context trees, but a different selected path.
        args=[str(binary),'publish','--workload','api','--context','copy api',
              '--dockerfile','copy api/Dockerfile','--project-name','demo',
              '--registry','localhost:5000','--commit',rev,'--evidence-dir',str(evidence),'--execute']
        result=cmd(args,repo,env,ok=False)
        assert 'different source/config/tool inputs' in result.stderr
        assert state(statefile) == original
        result=publish(binary,repo,rev,evidence,env,expect=False,extra=['--kind','frontend'])
        assert 'different source/config/tool inputs' in result.stderr
        assert state(statefile) == original
        publish(binary,repo,rev,evidence,env)
        assert state(statefile)['builds'] == 1


def test_config_source_guards(binary, base):
    for configured in (True, False):
        repo, rev, evidence, statefile, env=fixture(base/str(configured),binary,configured)
        for execute in (False, True):
            publish(binary,repo,rev,evidence,env,execute,False,extra=['--config','missing.toml'])
        assert not list(evidence.iterdir()) and state(statefile)['builds'] == 0
        # A selected config remains required/committed despite complete CLI overrides.
        target=repo/'devops.toml' if configured else repo/'api'/'message'
        original=target.read_bytes(); target.write_bytes(original+b'\n# changed\n')
        result=publish(binary,repo,rev,evidence,env,expect=False,extra=['--dockerfile','api/Dockerfile','--kind','backend'])
        assert 'not clean' in result.stderr and state(statefile)['builds'] == 0
        target.write_bytes(original)
        (repo/'api'/'untracked').write_text('not committed')
        result=publish(binary,repo,rev,evidence,env,expect=False)
        assert 'not clean' in result.stderr and state(statefile)['builds'] == 0
        assert not list(evidence.iterdir())

def test_build_arg_file_and_scan_policy(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary)
    argfile=repo/'api'/'build.env'; argfile.write_text('# committed build args\nMODE=release\n')
    (repo/'api'/'build-alt.env').write_text('MODE=debug\n')
    cmd(['git','add','api/build.env','api/build-alt.env'],repo,env); cmd(['git','commit','-m','add build arg files'],repo,env)
    rev=cmd(['git','rev-parse','HEAD'],repo,env).stdout.strip(); env['MOCK_REV']=rev
    set_state(statefile,expected_build_arg='MODE=release',expected_trivy_args=['--ignore-unfixed','--pkg-types','os'])
    extra=['--build-arg-file','api/build.env','--ignore-unfixed','--os-only']
    publish(binary,repo,rev,evidence,env,extra=extra)
    publish(binary,repo,rev,evidence,env,extra=extra)
    assert state(statefile)['builds'] == 1
    original=state(statefile)
    result=publish(binary,repo,rev,evidence,env,expect=False,extra=['--build-arg-file','api/build.env'])
    assert 'different source/config/tool inputs' in result.stderr and state(statefile) == original
    result=publish(binary,repo,rev,evidence,env,expect=False,extra=['--build-arg-file','api/build-alt.env','--ignore-unfixed','--os-only'])
    assert 'different source/config/tool inputs' in result.stderr and state(statefile) == original
    (repo/'api'/'build.env').write_text('MODE=debug\n')
    result=publish(binary,repo,rev,evidence,env,expect=False,extra=extra)
    assert 'not clean' in result.stderr and state(statefile) == original

def test_reuse_sealed(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary)
    original=json.loads(publish(binary,repo,rev,evidence,env).stdout)
    directory=evidence_dir(evidence,rev)
    sealed={p.name:p.read_bytes() for p in directory.iterdir() if p.name in json.loads((directory/'checksums.json').read_text())}
    alternate=base/('upgraded-tool.exe' if os.name == 'nt' else 'upgraded-tool')
    shutil.copy2(binary,alternate)
    with alternate.open('ab') as output: output.write(b'upgraded test binary\n')
    assert hashlib.sha256(binary.read_bytes()).hexdigest() != hashlib.sha256(alternate.read_bytes()).hexdigest()
    strict=publish(alternate,repo,rev,evidence,env,expect=False)
    assert 'different source/config/tool inputs' in strict.stderr
    # A prior scanner policy cannot be silently reused under today's gate.
    inputs_path=directory/'inputs.json'; original_inputs=inputs_path.read_bytes()
    legacy=json.loads(original_inputs); legacy['scan_policy']={'schema':0}
    inputs_path.write_text(json.dumps(legacy))
    refused=publish(alternate,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert 'different source/config/tool inputs' in refused.stderr and state(statefile)['builds']==1
    inputs_path.write_bytes(original_inputs)
    # 24h image cleanup must not invalidate durable publication evidence.
    set_state(statefile,local_images=[],require_local_artifact=True)
    result=json.loads(publish(alternate,repo,rev,evidence,env,extra=['--reuse-sealed']).stdout)
    assert result['result']=='published' and result['reused_sealed'] is True
    assert result['evidence_sha256']==original['evidence_sha256']
    assert Path(result['current_scan']).is_file() and Path(result['current_scanner']).is_file()
    assert result['scan_policy']['ignore_unfixed'] is False and result['scan_policy']['os_only'] is False
    assert result['scan_policy']['config']=='disabled'
    assert Path(result['current_secret_scan']).is_file()
    assert state(statefile)['builds']==1
    assert all((directory/name).read_bytes()==content for name,content in sealed.items())
    set_state(statefile,high_finding=True)
    failed=publish(alternate,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert 'Trivy gate failed' in failed.stderr and not failed.stdout
    assert state(statefile)['builds']==1
    assert all((directory/name).read_bytes()==content for name,content in sealed.items())
    set_state(statefile,high_finding=False)
    for extra in (['--reuse-sealed','--os-only'],['--reuse-sealed','--kind','frontend']):
        failed=publish(alternate,repo,rev,evidence,env,expect=False,extra=extra)
        assert 'different source/config/tool inputs' in failed.stderr
    path=repo/'api'/'message'; path.write_text('changed source\n')
    failed=publish(alternate,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert 'not clean' in failed.stderr
    assert state(statefile)['builds']==1
    path.write_text('committed payload\n')
    refs=state(statefile)['refs']; refs['localhost:5000/demo/api:candidate-'+rev]=MOVED
    set_state(statefile,refs=refs)
    failed=publish(alternate,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert 'candidate no longer matches sealed digest' in failed.stderr
    assert state(statefile)['builds']==1

def test_reuse_requires_complete(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary)
    set_state(statefile,scan_fail_once=True)
    publish(binary,repo,rev,evidence,env,expect=False)
    failed=publish(binary,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert 'reuse requires completed sealed publication' in failed.stderr
    assert state(statefile)['builds']==1

def test_scanner_policy_isolation_and_secret_gate(binary, base):
    repo, rev, evidence, statefile, env=fixture(base,binary)
    # Project files and caller variables must not control a publication gate.
    for filename in ('trivy.yaml', '.trivyignore', 'trivy-secret.yaml'):
        (repo/filename).write_text('caller-controlled\n')
    cmd(['git','add','.'],repo,env); cmd(['git','commit','-m','scanner override fixture'],repo,env)
    rev=cmd(['git','rev-parse','HEAD'],repo,env).stdout.strip(); env['MOCK_REV']=rev
    env.update({'TRIVY_CONFIG':'unsafe.yaml','TRIVY_SKIP_FILES':'*','TRIVY_IGNOREFILE':'.trivyignore',
                'TRIVY_EXIT_CODE':'0','TRIVY_SEVERITY':'CRITICAL','TRIVY_SCANNERS':'vuln'})
    set_state(statefile,secret_finding=True)
    failed=publish(binary,repo,rev,evidence,env,expect=False)
    assert 'secret gate failed' in failed.stderr and 'do-not-print' not in failed.stderr
    target='localhost:5000/demo/api:'+rev
    assert target not in state(statefile)['refs']
    directory=evidence_dir(evidence,rev)
    secret=json.loads((directory/'secret-scan.json').read_text())
    assert secret['Results'][0]['Secrets'][0]['Severity']=='LOW'
    assert not (directory/'checksums.json').exists()
    set_state(statefile,secret_finding=False)
    publish(binary,repo,rev,evidence,env)
    directory=evidence_dir(evidence,rev)
    seal=json.loads((directory/'checksums.json').read_text())
    assert 'secret-scan.json' in seal
    sealed=json.loads((directory/'evidence.json').read_text())
    assert sealed['scan_policy']['environment']=='TRIVY_* removed'
    assert sealed['secrets']['result']=='passed'
    set_state(statefile,secret_finding=True)
    publish(binary,repo,rev,evidence,env,expect=False,extra=['--reuse-sealed'])
    assert state(statefile)['builds']==1


def main():
    global WINDOWS_LAUNCHER
    parser=argparse.ArgumentParser(); parser.add_argument("binary",type=Path); args=parser.parse_args()
    if not args.binary.is_absolute() or not args.binary.is_file(): parser.error("binary must be an existing absolute path")
    binary=args.binary.resolve()
    with tempfile.TemporaryDirectory(prefix="devops-tool-publish-") as tmp:
        root=Path(tmp)
        if os.name == 'nt':
            source=root/'mock-launcher.rs'; source.write_text(LAUNCHER)
            WINDOWS_LAUNCHER=root/'mock-launcher.exe'
            cmd(['rustc',str(source),'-o',str(WINDOWS_LAUNCHER)],root,os.environ.copy())
        test_scanner_policy_isolation_and_secret_gate(binary,root/'scanner-isolation')
        print('PASS scanner-isolation')
        for name, test in (("plan",test_plan),("success-retry",test_success_retry),("scan-retry",test_scan_retry),("interrupted-build",test_interrupted_build),("build-metadata-marker",test_build_metadata_without_success_marker),("lookup-errors",test_lookup_errors),("conflicts-move",test_conflicts_and_move),("promote-tamper",test_promote_and_tamper),("scan-content",test_scan_content_gates),("no-config",test_no_config),("effective-inputs-retry",test_effective_inputs_retry),("config-source-guards",test_config_source_guards),("build-arg-policy",test_build_arg_file_and_scan_policy),("reuse-sealed",test_reuse_sealed),("reuse-incomplete",test_reuse_requires_complete)):
            test(binary,root/name); print("PASS",name)

if __name__ == "__main__": main()
