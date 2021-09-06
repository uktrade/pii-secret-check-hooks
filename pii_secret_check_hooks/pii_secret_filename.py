import argparse
import re

from pii_secret_check_hooks.util import get_excluded_filenames, get_regex


def detect_match_against_filename(filename, file_name_regexes):
    """checks argument against compiled regexes"""
    for regex in file_name_regexes:
        if re.search(regex, filename):
            return regex


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Files to check")
    parser.add_argument(
        "exclude",
        nargs=".pii-secret-exclude",
        help="List of files to exclude",
    )
    args = parser.parse_args(argv)

    exit_code = 0

    excluded_filenames = get_excluded_filenames(args.exclude)
    file_name_regex = get_regex("file_names.txt")

    for filename in args.filenames:
        if filename not in excluded_filenames:
            match = detect_match_against_filename(filename, file_name_regex)
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
