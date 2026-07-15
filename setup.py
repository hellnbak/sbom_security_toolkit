"""Compatibility installer for pip versions that predate PEP 660.

The canonical project metadata remains in pyproject.toml.  This file exists so
macOS systems that still ship pip 21.2.x can perform ``pip install -e .``.
"""
from pathlib import Path
from setuptools import find_packages, setup

ROOT = Path(__file__).parent
version_ns = {}
exec((ROOT / "sbomops" / "__version__.py").read_text(encoding="utf-8"), version_ns)

setup(
    name="sbom-security-toolkit",
    version=version_ns["__version__"],
    description="Local-first SBOM security operations, fuzzing, intake, evidence, and workbench toolkit.",
    long_description=(ROOT / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    python_requires=">=3.9",
    packages=find_packages(include=("sbomops", "sbomops.*", "ai_fuzz", "ai_fuzz.*")),
    include_package_data=True,
    package_data={"ai_fuzz": ["config/*.yml", "prompts/*.md"]},
    install_requires=[
        "fastapi>=0.111.0",
        "uvicorn[standard]>=0.30.0",
        "python-multipart>=0.0.9",
        "PyYAML>=6.0.1",
    ],
    extras_require={"dev": ["coverage>=7.5.0", "pytest>=8.0.0"]},
    entry_points={"console_scripts": ["sst=sbomops.cli:main"]},
)
