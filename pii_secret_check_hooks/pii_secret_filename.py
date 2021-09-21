import argparse

from pii_secret_check_hooks.util import get_excluded_filenames
from pii_secret_check_hooks.check_file.file_name import (
    check_file_names,
)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Files to check")
    parser.add_argument(
        "exclude",
        nargs="?",
        default=".pii-secret-exclude",
        help="Exclude file path",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)

    if check_file_names(args.filenames, excluded_filenames):
        return 1

    return 0


if __name__ == "__main__":
    exit(main())
