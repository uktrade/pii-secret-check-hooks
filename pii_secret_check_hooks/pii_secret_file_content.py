import argparse
import re

from util import get_excluded_filenames, get_regex

from truffleHogRegexes.regexChecks import trufflehog_regexes


def trufflehog_detect_secret_in_line(line_to_check):
    for regex in trufflehog_regexes:
        if re.search(regex, line_to_check):
            return regex


def pii_in_line(line_to_check):
    pii_regex = get_regex("pii.txt")

    for regex in pii_regex:
        if re.search(regex, line_to_check):
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

    for filename in args.filenames:
        if filename not in excluded_filenames:
            with open(filename, "r") as f:
                for i, line in enumerate(f):
                    if "#PS-IGNORE":
                        continue
                    rule = trufflehog_detect_secret_in_line(line, filename)
                    if rule:
                        print(
                            "Potentially sensitive string matching rule: {rule} found on line {line_number} of {file}".format(
                                rule=rule, line_number=i + 1, file=filename
                            )
                        )
                        exit_code = 1
    return exit_code


if __name__ == "__main__":
    exit(main())
