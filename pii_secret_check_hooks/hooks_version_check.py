import requests
import sys
from setup import setup


def check_release_version_from_remote_repo():
    """checks the GitHub API and returns the latest release tag detailed there"""
    try:
        req = requests.get(
            "https://github.com/uktrade/pii-secret-check-hooks/releases/latest"
        )
        content = req.json()
        return content["tag_name"]
    except:
        raise Exception("Remote checks failed")


def main():
    try:
        latest_release = check_release_version_from_remote_repo()
        setup_version = setup().version
        if setup_version == latest_release:
            print("All PII Secret hooks are up to date")
        else:
            print(
                f"Your pii-secret-check-hooks version is {setup_version} and latest is {latest_release}."
                ' Please run the following command in this directory: "pre-commit autoupdate"'

            )

    except Exception as e:
        print(
            "Checking for updates against PII Secret hooks failed ({error}). Run 'pre-commit autoupdate' in this directory as a precaution".format(
                error=e
            )
        )
    finally:
        return 0


if __name__ == "__main__":
    sys.exit(main())
