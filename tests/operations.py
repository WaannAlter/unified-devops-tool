#!/usr/bin/env python3
"""Offline Linux deadline/cancellation checks; no Docker daemon or live services."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def main():
    if sys.platform != "linux":
        raise SystemExit("Linux supervisor test; other OS execution is not certified")
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory(prefix="devops-tool-operations-") as temp:
        root = Path(temp)
        # Doctor runs version checks. A stalled dependency represents a hung
        # registry/engine child without stopping a real service.
        fake = root / "docker"
        fake.write_text("#!/bin/sh\nsleep 120 &\nchild=$!\necho $child > \"$CHILD_PID_FILE\"\nwait $child\n")
        fake.chmod(0o700)
        pid_file = root / "child.pid"
        env = dict(os.environ, PATH=temp + os.pathsep + os.environ["PATH"], CHILD_PID_FILE=str(pid_file))
        env.pop("DEVOPS_TOOL_SUPERVISED", None)

        def alive(pid):
            state = Path(f"/proc/{pid}/stat")
            return state.exists() and state.read_text().split(") ", 1)[1][0] != "Z"

        for cancelled in (False, True):
            pid_file.unlink(missing_ok=True)
            started = time.monotonic()
            proc = subprocess.Popen([binary, "--operation-timeout", "2", "doctor"], cwd=root, env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            try:
                until = time.monotonic() + 5
                while not pid_file.exists() and time.monotonic() < until:
                    time.sleep(0.05)
                assert pid_file.exists(), "doctor did not start dependency probe"
                child = int(pid_file.read_text())
                if cancelled:
                    proc.send_signal(signal.SIGTERM)
                proc.communicate(timeout=15)
                assert proc.returncode != 0, "timeout/cancellation must fail closed"
                assert time.monotonic() - started < 14
                for _ in range(20):
                    if not alive(child):
                        break
                    time.sleep(0.05)
                assert not alive(child), "descendant survived cancellation"
            finally:
                # The leader may already have exited while a broken supervisor
                # left a descendant holding the output pipes. We own this PGID.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                proc.wait()
            print("PASS", "cancel terminates descendants" if cancelled else "deadline terminates descendants")
        invalid = subprocess.run([binary, "--operation-timeout", "0", "doctor"], cwd=root, env=env,
                                 capture_output=True, timeout=5)
        assert invalid.returncode != 0
        print("PASS invalid timeout rejected")


if __name__ == "__main__":
    main()
