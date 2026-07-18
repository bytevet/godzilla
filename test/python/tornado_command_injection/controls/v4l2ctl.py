"""Untrusted device string interpolated into a shell command run via subprocess."""
import subprocess


def list_resolutions(device):
    cmd = f"v4l2-ctl -d '{device}' --list-formats-ext | grep -oE '[0-9]+x[0-9]+'"
    return subprocess.run(cmd, shell=True)
