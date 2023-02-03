from setuptools import setup, find_packages


def read(filename):
    with open(filename, "r") as fh:
        return fh.read()


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
            "pii-secret-file-content = pii_secret_check_hooks.pii_secret_file_content:main",
            "pii-secret-filename = pii_secret_check_hooks.pii_secret_filename:main",
            "pii-secret-file-version-check = pii_secret_check_hooks.hooks_version_check:main",
            "pii-secret-file-content-ner = pii_secret_check_hooks.pii_secret_file_content_ner:main",
        ]
    },
    packages=find_packages(),
    install_requires=[
        "setuptools",
        "wheel",
        "requests",
        "truffleHog",
        "pyyaml",
        "rich",
        "spacy >=3.5,<3.6",
        "en_core_web_sm@https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.5.0/en_core_web_sm-3.5.0.tar.gz",
    ],
    tests_require=["pytest"],
)
