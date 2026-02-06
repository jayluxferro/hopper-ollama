#!/usr/bin/env python3
"""
HopperOllama Uninstallation Script

Removes the HopperOllama script from your Hopper disassembler Scripts directory.

Usage:
    uv run uninstall.py [--confirm] [--dry-run]
"""

import sys
import os
import platform
import argparse


def get_hopper_script_dir():
    """Get Hopper script directory for current platform."""
    print("🔍 Determining Hopper Scripts directory...")
    system = platform.system().lower()
    home = os.path.expanduser("~")
    if system == "darwin":
        hopper_dir = os.path.join(home, "Library", "Application Support", "Hopper", "Scripts")
        print(f"   📁 macOS detected: {hopper_dir}")
    elif system == "linux":
        hopper_dir = os.path.join(home, "GNUstep", "Library", "ApplicationSupport", "Hopper", "Scripts")
        print(f"   📁 Linux detected: {hopper_dir}")
    else:
        raise OSError(f"❌ Unsupported platform: {system}. Only macOS and Linux are supported.")
    return hopper_dir


def find_installation():
    """Find existing HopperOllama installation."""
    print("🔍 Looking for existing installation...")
    hopper_dir = get_hopper_script_dir()
    script_path = os.path.join(hopper_dir, "hopper_ollama.py")
    if os.path.exists(script_path):
        print(f"   ✅ Found installation: {script_path}")
        return script_path
    print(f"   ❌ No installation found at: {script_path}")
    return None


def remove_installation(script_path, dry_run=False):
    """Remove the installation."""
    if dry_run:
        print(f"🔍 Would remove: {script_path}")
        return
    try:
        os.remove(script_path)
        print(f"✅ Successfully removed: {script_path}")
    except OSError as e:
        print(f"❌ Failed to remove {script_path}: {e}")
        raise


def show_dependency_info():
    """Show information about dependencies that user might want to clean up."""
    print("\n📦 Dependency Information:")
    print("   The following packages were installed by HopperOllama:")
    print("   • fastmcp")
    print("   • httpx")
    print("")
    print("   💡 If you want to remove these packages:")
    print("   • With uv: uv pip uninstall fastmcp httpx")
    print("   • With pip: pip uninstall fastmcp httpx")
    print("")
    print("   ⚠️  Warning: Only remove these if you're not using them elsewhere!")


def main():
    parser = argparse.ArgumentParser(description="Uninstall HopperOllama from Hopper Scripts directory")
    parser.add_argument("--confirm", action="store_true", help="Skip confirmation prompt")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without actually doing it")
    args = parser.parse_args()

    print("🗑️  HopperOllama Uninstallation Script")
    print("=" * 50)

    try:
        script_path = find_installation()
        if not script_path:
            print("❌ No HopperOllama installation found")
            print("💡 Nothing to uninstall")
            return

        if not args.confirm and not args.dry_run:
            response = input(f"\nRemove HopperOllama installation at {script_path}? (y/N): ")
            if response.lower() not in ("y", "yes"):
                print("❌ Uninstallation cancelled")
                return

        remove_installation(script_path, dry_run=args.dry_run)

        if not args.dry_run:
            print("\n" + "=" * 50)
            print("🎉 HopperOllama uninstalled successfully!")
            show_dependency_info()
        else:
            print("\n" + "=" * 50)
            print("🔍 Dry run completed - no changes made")

    except KeyboardInterrupt:
        print("\n❌ Uninstallation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Uninstallation failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
