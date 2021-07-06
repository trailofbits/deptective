import os
from setuptools import setup, find_packages

SETUP_DIR = os.path.dirname(os.path.realpath(__file__))
README_PATH = os.path.join(SETUP_DIR, "README.md")

with open(README_PATH, "r") as readme:
    README = readme.read()

setup(
    name="apt-trace",
    description="Auto satisfy dependencies in software",
    long_description=README,
    long_description_content_type="text/markdown",
    license="LGPL-3.0-or-later",
    url="https://github.com/trailofbits/apt-trace",
    author="Trail of Bits",
    version="0.0.1",
    packages=find_packages(exclude=["test"]),
    python_requires=">=3.7",
    install_requires=[python-ptrace
    ],
    extras_require={
        "dev": ["flake8", "twine", "mypy>=0.812"]
    },
    entry_points={
        "console_scripts": [
            "apt-trace = apt_trace.__main__:main"
        ]
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Utilities"
    ]
)
