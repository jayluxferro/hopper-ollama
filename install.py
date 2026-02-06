#!/usr/bin/env python3
"""
HopperOllama installation script.

Installs the HopperOllama script (and its dependencies) into Hopper's Scripts directory.
Uses uv by default; detects conda/venv and uses pyproject.toml.

Usage:
    uv run install.py [--force] [--dry-run]
"""

import sys
import os
import platform
import shutil
import subprocess
import argparse

def detect_python_environment():
    env_info = {
        "type": None,
        "package_manager": None,
        "environment_path": None,
    }
    if os.environ.get("CONDA_PREFIX"):
        env_info["type"] = "conda"
        env_info["package_manager"] = "conda"
        env_info["environment_path"] = os.environ["CONDA_PREFIX"]
    elif os.environ.get("VIRTUAL_ENV") or sys.prefix != sys.base_prefix:
        env_info["type"] = "venv"
        env_info["package_manager"] = "pip"
        env_info["environment_path"] = os.environ.get("VIRTUAL_ENV", sys.prefix)
    else:
        env_info["type"] = "system"
        env_info["package_manager"] = "pip"
        env_info["environment_path"] = sys.prefix
    if shutil.which("uv") and (os.path.exists("pyproject.toml") or os.path.exists("uv.lock")):
        env_info["package_manager"] = "uv"
    return env_info


def get_python_paths(env_info):
    import site
    if env_info["type"] == "conda":
        conda_prefix = os.environ["CONDA_PREFIX"]
        py_ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
        return {
            "lib_dynload": os.path.join(conda_prefix, "lib", py_ver, "lib-dynload"),
            "lib_path": os.path.join(conda_prefix, "lib", py_ver),
            "site_packages": os.path.join(conda_prefix, "lib", py_ver, "site-packages"),
        }
    try:
        site_packages = site.getsitepackages()[0]
    except (AttributeError, IndexError):
        site_packages = os.path.join(
            sys.prefix, "lib",
            f"python{sys.version_info.major}.{sys.version_info.minor}",
            "site-packages",
        )
    lib_path = os.path.dirname(site_packages)
    return {
        "lib_dynload": os.path.join(lib_path, "lib-dynload"),
        "lib_path": lib_path,
        "site_packages": site_packages,
    }


def get_hopper_script_dir():
    system = platform.system().lower()
    home = os.path.expanduser("~")
    if system == "darwin":
        return os.path.join(home, "Library", "Application Support", "Hopper", "Scripts")
    if system == "linux":
        return os.path.join(home, "GNUstep", "Library", "ApplicationSupport", "Hopper", "Scripts")
    raise OSError(f"Unsupported platform: {system}")


def install_dependencies(env_info, dry_run=False):
    if env_info["package_manager"] == "uv" and os.path.exists("pyproject.toml"):
        cmd = ["uv", "sync"]
    elif os.path.exists("pyproject.toml"):
        cmd = [sys.executable, "-m", "pip", "install", "-e", "."]
    else:
        return
    if dry_run:
        print(f"Would run: {' '.join(cmd)}")
        return
    subprocess.run(cmd, check=True)


def substitute_template(template_path, output_path, substitutions, dry_run=False):
    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()
    for k, v in substitutions.items():
        content = content.replace(k, v)
    if not dry_run:
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)


def main():
    parser = argparse.ArgumentParser(description="Install HopperOllama into Hopper Scripts")
    parser.add_argument("--force", action="store_true", help="Overwrite existing script")
    parser.add_argument("--dry-run", action="store_true", help="Only print what would be done")
    args = parser.parse_args()

    print("HopperOllama installer")
    print("=" * 50)
    env_info = detect_python_environment()
    paths = get_python_paths(env_info)
    template_path = "hopper_ollama_template.py"
    if not os.path.exists(template_path):
        print(f"Template not found: {template_path}")
        sys.exit(1)
    install_dependencies(env_info, dry_run=args.dry_run)
    configured = "hopper_ollama_configured.py"
    substitute_template(
        template_path,
        configured,
        {
            "{{PYTHON_LIB_DYNLOAD}}": paths["lib_dynload"],
            "{{PYTHON_LIB_PATH}}": paths["lib_path"],
            "{{PYTHON_SITE_PACKAGES}}": paths["site_packages"],
        },
        dry_run=args.dry_run,
    )
    hopper_dir = get_hopper_script_dir()
    target = os.path.join(hopper_dir, "hopper_ollama.py")
    if args.dry_run:
        print(f"Would copy to: {target}")
    else:
        if os.path.exists(target) and not args.force:
            r = input(f"Overwrite {target}? (y/N): ")
            if r.lower() not in ("y", "yes"):
                sys.exit(1)
        os.makedirs(hopper_dir, exist_ok=True)
        shutil.copy2(configured, target)
        if os.path.exists(configured):
            os.remove(configured)
        print(f"Installed: {target}")
    print("=" * 50)
    print("Next: open Hopper, run the hopper_ollama script from Scripts. See README for usage.")


if __name__ == "__main__":
    main()
