"""Setup configuration for analyzer package."""
from setuptools import setup, find_packages

setup(
    name="postbuild-analyzer",
    version="1.0.0",
    description="Automated post-build code analysis agent for Python projects",
    author="GitHub Copilot",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=3.0",
            "bandit>=1.7",
            "flake8>=4.0",
            "mypy>=0.950",
            "ruff>=0.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "postbuild-analyzer=analyzer.postbuild_analyzer:main",
        ],
    },
)
