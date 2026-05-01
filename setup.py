"""
JSPECTER setup.py
Enables: pip install .
         jspecter (global command)
"""

from setuptools import setup, find_packages
import os

# Read long description from README
here = os.path.abspath(os.path.dirname(__file__))
try:
    with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
        long_description = f.read()
except FileNotFoundError:
    long_description = "JSPECTER - Autonomous JavaScript Recon & Vulnerability Intelligence Engine"

setup(
    name="jspecter",
    version="1.0.0",
    author="JSPECTER Contributors",
    description="Autonomous JavaScript Recon, Secret Discovery & Vulnerability Intelligence Engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/abhi04anon/jspecter",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "aiohttp>=3.9.0",
        "aiofiles>=23.0.0",
    ],
    extras_require={
        "git": ["gitpython>=3.1.0"],
        "dev": [
            "pytest>=7.0",
            "pytest-asyncio>=0.21",
            "black>=23.0",
            "mypy>=1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "jspecter=jspecter.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords="security bugbounty javascript recon pentest vulnerability CVE secrets",
    project_urls={
        "Bug Reports": "https://github.com/abhi04anon/jspecter/issues",
        "Source": "https://github.com/abhi04anon/jspecter",
        "Documentation": "https://github.com/abhi04anon/jspecter#readme",
    },
)
