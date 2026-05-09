"""
Setup configuration for linux-privesc-toolkit.
Install with: pip install -e .
"""
from setuptools import setup, find_packages
import os

# Read long description from README
here = os.path.abspath(os.path.dirname(__file__))
with open(os.path.join(here, "README.md"), encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="linux-privesc-toolkit",
    version="2.1.0",
    description="Automated Linux privilege escalation detection scanner — detection-only, safe enumeration",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Nitesh Ghimire",
    author_email="ghimirenitesh8@gmail.com",
    url="https://github.com/niteshghimire/linux-privesc-toolkit",
    license="MIT",
    python_requires=">=3.6",
    packages=find_packages(exclude=["tests*", "output*"]),
    package_data={
        "": ["data/*.json"],
    },
    entry_points={
        "console_scripts": [
            "privesc-scan=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    keywords="security pentest privilege-escalation linux audit suid gtfobins cve",
)
