import logging
import requests
import yaml
import sys
from rich.console import Console

from pii_secret_check_hooks.config import RELEASE_CHECK_URL

console = Console()


def check_release_version_from_config(pre_commit_config_yaml):
    """checks the pre-commit-config.yaml in the current directory and returns the release tag detailed there"""
    with open(pre_commit_config_yaml, "r") as file:
        config = yaml.safe_load(file)
        res = filter(lambda x: "pii-secret-check-hooks" in x["repo"], config["repos"])
        return next(res)["rev"]


def check_release_version_from_remote_repo():
    req = requests.get(
        RELEASE_CHECK_URL,
        headers={
            "Accept": "application/vnd.github.v3+json",
        },
    )
    content = req.json()
    return content["tag_name"]


def main():
    try:
        config_version = check_release_version_from_config(".pre-commit-config.yaml")
        latest_release = check_release_version_from_remote_repo()
        if config_version == latest_release:
            console.print(
                "All DIT PII and DIT security hooks are up to date",
                style="white on green",
                soft_wrap=True,
            )
            return 0
        else:
            console.print(
                "Your pii-secret-check-hooks version is {yours} and latest is {latest}."
                ' Please run the following command in this directory: "pre-commit autoupdate"'.format(
                    yours=config_version, latest=latest_release
                ),
                style="red",
                soft_wrap=True,
            )
            return 1

    except Exception as e:
        console.print(
            f"Checking for updates against DIT PII and security hooks failed ({e}). "
            "Run 'pre-commit autoupdate' in this directory as a precaution",
            style="red",
            soft_wrap=True,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
