#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later OR LGPL-3.0-or-later
"""QEMU/KVM + cloud-init test VM manager for eBPFDivert (replaces Vagrant)."""

from __future__ import annotations

import argparse
import os
import shlex
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CACHE_DIR = Path(os.environ.get("DIVERT_VM_CACHE", Path.home() / ".cache" / "divert-vm"))
IMAGES_DIR = CACHE_DIR / "images"
RUNS_DIR = CACHE_DIR / "runs"
SSH_KEY = CACHE_DIR / "id_ed25519"

PACKAGES = [
    "clang",
    "llvm",
    "make",
    "gcc",
    "pkg-config",
    "libelf-dev",
    "zlib1g-dev",
    "ethtool",
    "iproute2",
]

TARGETS = {
    "default": {
        "hostname": "ebpfdivert",
        "image_name": "noble-server-cloudimg-amd64.img",
        "image_url": "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img",
        "memory_mb": 2048,
        "cpus": 2,
    },
    "legacy": {
        "hostname": "ebpfdivert-legacy",
        "image_name": "jammy-server-cloudimg-amd64.img",
        "image_url": "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img",
        "memory_mb": 2048,
        "cpus": 2,
    },
}


def run_dir_for(target: str) -> Path:
    return RUNS_DIR / f"ebpfdivert-{target}"


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def ensure_tools() -> str:
    for tool in ("qemu-system-x86_64", "qemu-img", "ssh", "ssh-keygen"):
        if shutil.which(tool) is None:
            sys.exit(f"Missing required tool '{tool}'. Install QEMU and OpenSSH first.")
    for iso_tool in ("cloud-localds", "genisoimage", "mkisofs", "xorrisofs"):
        if shutil.which(iso_tool) is not None:
            return iso_tool
    sys.exit("Missing ISO builder (install cloud-localds, genisoimage, mkisofs, or xorrisofs).")


def ensure_ssh_key() -> str:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not SSH_KEY.exists():
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", str(SSH_KEY)],
            check=True,
        )
    return SSH_KEY.with_suffix(".pub").read_text().strip()


def ensure_image(target: str) -> Path:
    IMAGES_DIR.mkdir(parents=True, exist_ok=True)
    spec = TARGETS[target]
    dest = IMAGES_DIR / spec["image_name"]
    if dest.exists():
        return dest
    part = dest.with_suffix(".img.part")
    print(f"Downloading {spec['image_url']} -> {dest} ...")
    try:
        with urllib.request.urlopen(spec["image_url"]) as resp, open(part, "wb") as out:
            shutil.copyfileobj(resp, out, length=1024 * 1024)
        part.rename(dest)
    except Exception:
        part.unlink(missing_ok=True)
        raise
    return dest


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def check_single_vm(active_target: str) -> None:
    if not RUNS_DIR.exists():
        return
    for entry in RUNS_DIR.iterdir():
        pid_file = entry / "qemu.pid"
        if not pid_file.exists():
            continue
        pid = int(pid_file.read_text().strip())
        if pid_alive(pid):
            if entry.name == f"ebpfdivert-{active_target}":
                return
            sys.exit(
                f"Another VM is already running ({entry.name}, pid {pid}). "
                "Destroy it first to obey the one-VM-at-a-time policy."
            )


def build_seed_iso(rdir: Path, target: str, pubkey: str, iso_tool: str) -> Path:
    spec = TARGETS[target]
    meta_data = rdir / "meta-data"
    user_data = rdir / "user-data"
    seed_iso = rdir / "seed.iso"

    meta_data.write_text(
        f"instance-id: ebpfdivert-{target}\n"
        f"local-hostname: {spec['hostname']}\n"
    )
    pkg_lines = "\n".join(f"  - {p}" for p in PACKAGES)
    user_data.write_text(
        "#cloud-config\n"
        "users:\n"
        "  - name: divert\n"
        "    sudo: ALL=(ALL) NOPASSWD:ALL\n"
        "    shell: /bin/bash\n"
        "    lock_passwd: true\n"
        "    ssh_authorized_keys:\n"
        f"      - {pubkey}\n"
        "package_update: true\n"
        "packages:\n"
        f"{pkg_lines}\n"
        "runcmd:\n"
        "  - mkdir -p /workspace\n"
        "  - mount -t 9p -o trans=virtio,version=9p2000.L,msize=104857600 workspace /workspace\n"
    )

    if iso_tool == "cloud-localds":
        subprocess.run(["cloud-localds", str(seed_iso), str(user_data), str(meta_data)], check=True)
    else:
        subprocess.run(
            [
                iso_tool,
                "-output",
                str(seed_iso),
                "-volid",
                "cidata",
                "-joliet",
                "-rock",
                str(user_data),
                str(meta_data),
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return seed_iso


def ssh_base(port: int) -> list[str]:
    return [
        "ssh",
        "-i",
        str(SSH_KEY),
        "-p",
        str(port),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        "divert@127.0.0.1",
    ]


def wait_for_ssh(port: int, pid: int, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if not pid_alive(pid):
            sys.exit("QEMU exited unexpectedly while waiting for SSH. Check console.log.")
        res = subprocess.run(
            [*ssh_base(port), "cloud-init status --wait >/dev/null 2>&1 || true; echo ready"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        if res.returncode == 0 and "ready" in res.stdout:
            return
        time.sleep(2)
    sys.exit(f"Timed out after {timeout}s waiting for VM SSH / cloud-init.")


def cmd_up(target: str) -> int:
    iso_tool = ensure_tools()
    check_single_vm(target)
    rdir = run_dir_for(target)
    pid_file = rdir / "qemu.pid"
    if pid_file.exists() and pid_alive(int(pid_file.read_text().strip())):
        port = int((rdir / "ssh.port").read_text().strip())
        print(f"{target} already running (ssh port {port})")
        return port

    shutil.rmtree(rdir, ignore_errors=True)
    rdir.mkdir(parents=True, exist_ok=True)
    pubkey = ensure_ssh_key()
    base_img = ensure_image(target)
    overlay = rdir / "overlay.qcow2"
    subprocess.run(
        ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b", str(base_img), str(overlay), "20G"],
        check=True,
        stdout=subprocess.DEVNULL,
    )
    seed_iso = build_seed_iso(rdir, target, pubkey, iso_tool)
    port = free_port()
    (rdir / "ssh.port").write_text(str(port))

    spec = TARGETS[target]
    qemu_cmd = [
        "qemu-system-x86_64",
        "-name",
        f"ebpfdivert-{target}",
        "-m",
        str(spec["memory_mb"]),
        "-smp",
        str(spec["cpus"]),
        "-drive",
        f"file={overlay},if=virtio,format=qcow2",
        "-drive",
        f"file={seed_iso},media=cdrom,readonly=on",
        "-netdev",
        f"user,id=net0,hostfwd=tcp:127.0.0.1:{port}-:22",
        "-device",
        "virtio-net-pci,netdev=net0",
        "-virtfs",
        f"local,path={REPO_ROOT},mount_tag=workspace,security_model=mapped-xattr,id=workspace",
        "-nographic",
        "-daemonize",
        "-pidfile",
        str(pid_file),
        "-serial",
        f"file:{rdir / 'console.log'}",
    ]
    if Path("/dev/kvm").exists() and os.access("/dev/kvm", os.R_OK | os.W_OK):
        qemu_cmd.extend(["-enable-kvm", "-cpu", "host"])
    else:
        print("Warning: /dev/kvm unavailable; running without KVM acceleration.", file=sys.stderr)
        qemu_cmd.extend(["-cpu", "max"])

    subprocess.run(qemu_cmd, check=True)
    pid = int(pid_file.read_text().strip())
    print(f"Booting {target} (pid {pid}, ssh port {port})...")
    wait_for_ssh(port, pid)
    return port


def get_port(target: str) -> int:
    rdir = run_dir_for(target)
    pid_file = rdir / "qemu.pid"
    if not pid_file.exists() or not pid_alive(int(pid_file.read_text().strip())):
        sys.exit(f"VM '{target}' is not running. Start it with: python3 scripts/vm.py up {target}")
    return int((rdir / "ssh.port").read_text().strip())


def cmd_exec(target: str, command: str) -> int:
    port = get_port(target)
    res = subprocess.run([*ssh_base(port), command])
    return res.returncode


def cmd_ssh(target: str, args: list[str]) -> int:
    port = get_port(target)
    if args:
        return subprocess.run([*ssh_base(port), shlex.join(args)]).returncode
    return subprocess.run(ssh_base(port)).returncode


def cmd_destroy(target: str) -> None:
    rdir = run_dir_for(target)
    pid_file = rdir / "qemu.pid"
    if pid_file.exists():
        pid = int(pid_file.read_text().strip())
        if pid_alive(pid):
            os.kill(pid, 15)
            for _ in range(20):
                if not pid_alive(pid):
                    break
                time.sleep(0.25)
            if pid_alive(pid):
                os.kill(pid, 9)
    shutil.rmtree(rdir, ignore_errors=True)
    print(f"Destroyed {target}")


def cmd_run(target: str, extra: list[str]) -> int:
    try:
        cmd_up(target)
        quoted_args = " ".join(shlex.quote(a) for a in extra)
        script = (
            "set -euo pipefail; "
            "rm -rf /tmp/work && cp -a /workspace /tmp/work && cd /tmp/work; "
            "make clean && make -j$(nproc) && ./test_filter && "
            "sudo ./test_bpf ebpfdivert.bpf.o && "
            f"sudo ./tests/run_integration_tests.sh {quoted_args}"
        )
        return cmd_exec(target, f"bash -lc {shlex.quote(script)}")
    finally:
        cmd_destroy(target)


def cmd_status() -> None:
    for target in TARGETS:
        rdir = run_dir_for(target)
        pid_file = rdir / "qemu.pid"
        if pid_file.exists():
            pid = int(pid_file.read_text().strip())
            if pid_alive(pid):
                port = (rdir / "ssh.port").read_text().strip()
                print(f"{target}: running (pid {pid}, ssh port {port})")
                continue
        print(f"{target}: stopped")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage QEMU/KVM test VMs for eBPFDivert")
    sub = parser.add_subparsers(dest="cmd", required=True)

    for name in ("up", "destroy"):
        p = sub.add_parser(name)
        p.add_argument("target", choices=TARGETS.keys(), default="default", nargs="?")

    p_exec = sub.add_parser("exec")
    p_exec.add_argument("target", choices=TARGETS.keys())
    p_exec.add_argument("command")

    p_ssh = sub.add_parser("ssh")
    p_ssh.add_argument("target", choices=TARGETS.keys(), default="default", nargs="?")
    p_ssh.add_argument("args", nargs=argparse.REMAINDER)

    p_run = sub.add_parser("run")
    p_run.add_argument("target", choices=TARGETS.keys(), default="default", nargs="?")
    p_run.add_argument("args", nargs=argparse.REMAINDER)

    sub.add_parser("status")

    args = parser.parse_args()
    if args.cmd == "up":
        cmd_up(args.target)
    elif args.cmd == "destroy":
        cmd_destroy(args.target)
    elif args.cmd == "exec":
        sys.exit(cmd_exec(args.target, args.command))
    elif args.cmd == "ssh":
        sys.exit(cmd_ssh(args.target, args.args))
    elif args.cmd == "run":
        sys.exit(cmd_run(args.target, args.args))
    elif args.cmd == "status":
        cmd_status()


if __name__ == "__main__":
    main()
