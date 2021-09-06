from setuptools import setup, find_packages
from codecs import open
import os


def read(filename):
    return open(os.path.join(os.path.dirname(__file__), filename)).read()


setup(
    name="pii-security-check-hooks",
    author="DIT security pre-commit checks",
    author_email="ross.miller@digital.trade.gov.uk",
    version=read(".version"),
    description="Detect PII and secrets prior to commit",
    url="https://github.com/uktrade/pii-secret-check-hooks",
    long_description=read("README.md"),
    entry_points={
        "console_scripts": [
            "pii-secret-file-content = security_git_hooks.secrets_filecontent:main",
            "pii-secret-filename = security_git_hooks.secrets_filename:main",
            "pii-secret-file-version-check = security_git_hooks.hooks_version_check:main",
        ]
    },
    packages=find_packages(),
    install_requires=["truffleHogRegexes", "requests"],
    tests_require=["pytest"],
)
