from setuptools import setup

def read_file(fname):
    with open(fname, 'r') as f:
        return f.read()

setup(name = "uvscand",
    version = "0.0.4",
    author = "Thomas Oettli",
    author_email = "spacefreak@noop.ch",
    description = "A python daemon to perform virus scans with uvscan (McAfee) over TCP socket.",
    license = "GPL 3",
    keywords = "rspamd uvscan",
    url = "https://github.com/spacefreak86/uvscand",
    packages = ["uvscand"],
    long_description = read_file("README.md"),
    classifiers = [
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Communications :: Email :: Virus"
    ],
    entry_points = {
        "console_scripts": [
            "uvscand=uvscand:main"
        ]
    },
    python_requires = ">=3"
)
