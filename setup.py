from sys import platform
from setuptools import setup, find_packages


README = open("README.md", "r").read()
DEPENDENCIES = open("requirements.txt", "r").read().split("\n")
if platform == "win32":
    DEPENDENCIES += ["colorama", "pyreadline"]

setup(name = "routersploit",
      version = "3.4.0",
      description = "Exploitation Framework for Embedded Devices",
      long_description = README,
      author = "Threat9",
      author_email = "marcin@threat9.com",
      url = "https://www.threat9.com",
      download_url = "https://github.com/threat9/routersploit/",
      packages = find_packages(),
      include_package_data = True,
      scripts = ("rsf.py",),
      entry_points = {},
      install_requires = DEPENDENCIES,
      extras_require = {
        "tests": [
            "pytest",
            "pytest-forked",
            "pytest-xdist",
            "flake8",
        ],
      },
      classifiers = [
        "Operating System :: POSIX",
        "Environment :: Console",
        "Environment :: Console :: Curses",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Intended Audience :: Developers",
        "Intended Audience :: Education",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Telecommunications Industry",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: Utilities",
      ],
)
