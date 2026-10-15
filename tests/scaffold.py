#!/usr/bin/env python3
"""Exercise generated files using disposable projects, never application checkouts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(command, cwd, *, env=None, ok=True, timeout=300):
    result = subprocess.run(command, cwd=cwd, text=True, capture_output=True,
                            env=env, timeout=timeout)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != ok:
        raise AssertionError(f'{command}\n{output}')
    return output


def fixture(root, template):
    root.mkdir()
    if template == 'rust':
        (root / 'src').mkdir()
        (root / 'Cargo.toml').write_text(
            '[package]\nname="scaffold-proof"\nversion="0.1.0"\nedition="2024"\n')
        (root / 'Cargo.lock').write_text(
            'version = 4\n[[package]]\nname = "scaffold-proof"\nversion = "0.1.0"\n')
        (root / 'src/main.rs').write_text('''use std::io::{Read, Write};
use std::net::TcpListener;
fn message() -> &'static str { "scaffold-proof" }
fn main() {
    let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
    for stream in TcpListener::bind(format!("0.0.0.0:{port}")).unwrap().incoming() {
        let mut stream = stream.unwrap();
        let mut request = [0; 2048];
        let _ = stream.read(&mut request);
        let body = message();
        write!(stream, "HTTP/1.1 200 OK\\r\\nContent-Length: {}\\r\\nConnection: close\\r\\n\\r\\n{}", body.len(), body).unwrap();
    }
}
#[test] fn proves_test_stage() {
    assert_eq!(message(), "scaffold-proof");
    for path in [".env", ".ssh/id_ed25519", "private.key", "private.pem", "secrets/token.txt"] {
        assert!(!std::path::Path::new(path).exists(), "secret sentinel entered context: {path}");
    }
}
''')
    else:
        name = 'scaffold-' + template
        package = dict(name=name, version='1.0.0', private=True, type='module', scripts={
            'build': 'node build.mjs' if template == 'npm-static' else 'bun build.mjs',
            'test': 'node --test test.mjs' if template == 'npm-static' else 'bun test',
        })
        (root / 'package.json').write_text(json.dumps(package))
        if template == 'npm-static':
            (root / 'package-lock.json').write_text(json.dumps(dict(
                name=name, version='1.0.0', lockfileVersion=3, requires=True,
                packages={'': dict(name=name, version='1.0.0')})))
            (root / 'test.mjs').write_text(
                'import {test} from "node:test"; import assert from "node:assert/strict"; '
                'import {existsSync} from "node:fs"; '
                'test("fixture",()=>{assert.equal(1+1,2); '
                'for(const p of [".env",".ssh/id_ed25519","private.key","private.pem","secrets/token.txt"]) '
                '{assert.equal(existsSync(p),false,p);}});\n')
        else:
            # Bun removes empty locks; one tiny pinned package proves frozen installation.
            package['dependencies'] = {'is-number': '7.0.0'}
            (root / 'package.json').write_text(json.dumps(package))
            (root / 'bun.lock').write_text(json.dumps(dict(
                lockfileVersion=2, configVersion=1,
                workspaces={'': dict(name=name, dependencies=package['dependencies'])},
                packages={'is-number': ['is-number@7.0.0', '', {},
                    'sha512-41Cifkg6e8TylSpdtTpeLVMqvSBEVzTttHvERD741+pnZ8ANv0004MRL43QKPDlK9cGvNp6NZWZUBlbGXYxxng==']})))
            (root / 'test.test.js').write_text(
                'import {test,expect} from "bun:test"; import {existsSync} from "node:fs"; '
                'test("fixture",()=>{expect(1+1).toBe(2); '
                'for(const p of [".env",".ssh/id_ed25519","private.key","private.pem","secrets/token.txt"]) '
                '{expect(existsSync(p)).toBe(false);}});\n')
        (root / 'build.mjs').write_text(
            'import {mkdirSync,writeFileSync} from "node:fs"; mkdirSync("dist",{recursive:true}); '
            'writeFileSync("dist/index.html","scaffold-proof");\n')
    # Synthetic sentinel: prove ignores, not real credentials.
    (root / '.env').write_text('SCAFFOLD_SENTINEL=must-not-enter-image\n')
    for name in ('.ssh/id_ed25519', 'private.key', 'private.pem', 'secrets/token.txt'):
        target = root / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text('SCAFFOLD_SENTINEL=must-not-enter-image\n')


def prove(binary, root, template, execute, scan):
    print('START generated template ' + template, flush=True)
    project = root / template
    fixture(project, template)
    args = [str(binary), 'scaffold', '--template', template, '--context', str(project)]
    if template == 'rust':
        args += ['--health-path', '/healthz']
    before = set(project.iterdir())
    preview = run(args, root)
    assert '--- Dockerfile ---' in preview
    assert 'FROM test AS build' in preview, 'runtime build bypasses tests'
    assert set(project.iterdir()) == before, 'preview wrote files'
    run(args + ['--execute'], root)
    names = ['Dockerfile', '.dockerignore', 'compose.yaml']
    if template != 'rust':
        names += ['scaffold.nginx.conf']
    digests = {name: hashlib.sha256((project / name).read_bytes()).hexdigest() for name in names}
    run(args + ['--execute'], root, ok=False)
    assert digests == {name: hashlib.sha256((project / name).read_bytes()).hexdigest() for name in names}
    run(['git', 'init', '-q'], project)
    run(['git', 'add', '.'], project)
    run(['git', '-c', 'user.name=Scaffold fixture', '-c', 'user.email=fixture@localhost',
         'commit', '-qm', 'generated scaffold fixture'], project)
    kind = 'backend' if template == 'rust' else 'frontend'
    build_args = ['--kind', kind, '--project-name', 'scaffold-proof-' + template]
    assert 'result\tvalid' in run([str(binary), 'validate', *build_args], project)
    result = dict(template=template, files=digests, preview_no_write=True, overwrite_denied=True)
    if not execute:
        print('PASS ' + json.dumps(result), flush=True)
        return
    run([str(binary), 'check', *build_args, '--target', 'test', '--execute'], project, timeout=900)
    started = time.monotonic()
    output = run([str(binary), 'build', *build_args, '--execute'], project, timeout=900)
    first = round(time.monotonic() - started, 3)
    image = next(line.split('\t', 1)[1] for line in output.splitlines() if line.startswith('image\t'))
    container = 'scaffold-' + template + '-' + str(os.getpid())
    environment = dict(os.environ, IMAGE_REF=image, BUILDKIT_PROGRESS='plain')
    try:
        run([str(binary), 'verify', *build_args], project)
        if scan:
            run([str(binary), 'scan', *build_args, '--execute'], project, timeout=900)
        config = json.loads(run(['docker', 'image', 'inspect', image], project))[0]['Config']
        assert config['User'] not in ('', '0', 'root', '0:0'), config['User']
        compose = json.loads(run(['docker', 'compose', '-f', 'compose.yaml', 'config', '--format', 'json'],
                                 project, env=environment))['services']['app']
        assert compose['read_only'] and compose['ports'][0]['host_ip'] == '127.0.0.1'
        assert 'ALL' in compose['cap_drop'] and compose['image'] == image
        command = ['docker', 'run', '--detach', '--name', container, '--read-only', '--network', 'none',
                   '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                   '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m', '--memory', '128m',
                   '--cpus', '0.5', image]
        run(command, project)
        client = ['curl', '--fail', '--silent', '--show-error'] if template == 'rust' else ['wget', '-q', '-O', '-']
        for attempt in range(30):
            try:
                run(['docker', 'exec', container, *client, 'http://127.0.0.1:8080/healthz'], project, timeout=10)
                assert 'scaffold-proof' in run(['docker', 'exec', container, *client, 'http://127.0.0.1:8080/'], project, timeout=10)
                break
            except (AssertionError, OSError, subprocess.TimeoutExpired):
                if attempt == 29:
                    raise AssertionError(run(['docker', 'logs', container], project))
                time.sleep(1)
        # Test the actual generated Compose service too, without fixed-host-port conflicts.
        compose_file = project / 'compose.yaml'
        text = compose_file.read_text()
        assert '"127.0.0.1:8080:8080"' in text
        compose_file.write_text(text.replace('"127.0.0.1:8080:8080"', '"127.0.0.1::8080"'))
        compose_cmd = ['docker', 'compose', '-p', container, '-f', 'compose.yaml']
        try:
            run(compose_cmd + ['up', '-d', '--wait', '--wait-timeout', '60'], project, env=environment)
        finally:
            run(compose_cmd + ['down'], project, env=environment)
            compose_file.write_text(text)
        started = time.monotonic()
        warm = run([str(binary), 'build', *build_args, '--execute'], project, timeout=900)
        assert 'CACHED' in warm, warm
        result.update(build_seconds=first, warm_seconds=round(time.monotonic() - started, 3),
                      image=image, runtime=True, compose=True, non_root=True, warm_cached=True,
                      scanned=scan)
        print('PASS ' + json.dumps(result), flush=True)
    finally:
        # Cleanup must not mask the original failure; identifiers are owned fixture targets.
        subprocess.run(['docker', 'rm', '--force', container], cwd=project, capture_output=True)
        subprocess.run(['docker', 'image', 'rm', image], cwd=project, capture_output=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--execute', action='store_true', help='Allow local fixture Docker builds/runs')
    parser.add_argument('--scan', action='store_true', help='Require runtime vulnerability/secret scans with the SDK')
    args = parser.parse_args()
    if args.scan and not args.execute:
        parser.error('--scan requires --execute')
    binary = args.binary.resolve()
    if not binary.is_file():
        parser.error('binary does not exist')
    with tempfile.TemporaryDirectory(prefix='devops-tool-scaffold-proof-') as temporary:
        root = Path(temporary)
        for template in ('rust', 'npm-static', 'bun-static'):
            prove(binary, root, template, args.execute, args.scan)
    print('PASS scaffold proof; only owned fixtures removed, build cache retained', flush=True)


if __name__ == '__main__':
    main()
