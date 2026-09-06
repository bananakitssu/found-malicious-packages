#!/usr/bin/env python3
"""Shared ecosystem metadata for Authtics scanners."""

from dataclasses import dataclass


@dataclass(frozen=True)
class EcosystemConfig:
    key: str
    display_name: str
    advisory_ecosystem: str
    package_root: str
    package_manifest: str
    registry_url: str
    install_script_names: tuple[str, ...]
    source_extensions: tuple[str, ...]


ECOSYSTEMS = {
    "npm": EcosystemConfig(
        key="npm",
        display_name="npm",
        advisory_ecosystem="npm",
        package_root="package",
        package_manifest="package.json",
        registry_url="https://registry.npmjs.org/",
        install_script_names=("preinstall", "install", "postinstall", "prepare"),
        source_extensions=(".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".sh", ".bash"),
    ),
    "pypi": EcosystemConfig(
        key="pypi",
        display_name="PyPI",
        advisory_ecosystem="PyPI",
        package_root="package",
        package_manifest="pyproject.toml",
        registry_url="https://pypi.org/",
        install_script_names=("setup.py", "setup.cfg", "pyproject.toml"),
        source_extensions=(".py", ".pyi", ".pyw", ".json", ".toml", ".cfg", ".ini", ".sh", ".bash"),
    ),
}


def get_ecosystem(name: str) -> EcosystemConfig:
    key = name.strip().lower()
    try:
        return ECOSYSTEMS[key]
    except KeyError as exc:
        raise ValueError(f"Unsupported ecosystem: {name}") from exc
