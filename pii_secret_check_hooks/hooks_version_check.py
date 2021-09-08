import logging
import requests
import yaml
import sys

from pii_secret_check_hooks.config import RELEASE_CHECK_URL


def check_release_version_from_config(pre_commit_config_yaml):
    """checks the pre-commit-config.yaml in the current directory and returns the release tag detailed there"""
    with open(pre_commit_config_yaml, "r") as file:
        config = yaml.safe_load(file)
        res = filter(lambda x: "security-git-hooks" in x["repo"], config["repos"])
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
            logging.info("All DIT PII and DIT security hooks are up to date")
            return 0
        else:
            logging.info(
                "Your pii-secret-check-hooks version is {yours} and latest is {latest}."
                ' Please run the following command in this directory: "pre-commit autoupdate"'.format(
                    yours=config_version, latest=latest_release
                )
            )
            return 1

    except Exception as e:
        logging.error(
            "Checking for updates against DIT PII and security hooks failed ({error}). "
            "Run 'pre-commit autoupdate' in this directory as a precaution".format(
                error=e
            )
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
