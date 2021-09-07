import argparse
import re

from pii_secret_check_hooks.util import get_excluded_filenames
from pii_secret_check_hooks.config import filename_regex


def detect_match_against_filename(filename, file_name_regexes):
    for regex in file_name_regexes:
        if re.search(regex, filename):
            return regex


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Files to check")
    parser.add_argument(
        "exclude",
        nargs=1,
        default=".pii-secret-exclude",
        help="Exclude file path",
    )
    args = parser.parse_args(argv)

    exit_code = 0

    excluded_filenames = get_excluded_filenames(args.exclude[0])

    for filename in args.filenames:
        if filename not in excluded_filenames:
            match = detect_match_against_filename(filename, filename_regex)
            if match:
                exit_code = 1
                print(
                    "{file} may contain sensitive information due to the file type".format(
                        file=filename
                    )
                )

    return exit_code


if __name__ == "__main__":
    exit(main())
