import argparse
import re

from pii_secret_check_hooks.util import get_excluded_filenames, get_regex

from truffleHogRegexes.regexChecks import regexes as trufflehog_regexes


PII_REGEX = get_regex("pii.txt")


def trufflehog_detect_secret_in_line(line_to_check):
    for regex in trufflehog_regexes:
        if re.search(regex, line_to_check):
            return regex


def pii_in_line(line_to_check):
    for regex in PII_REGEX:
        if re.search(regex, line_to_check):
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

    excluded_filenames = get_excluded_filenames(args.exclude)

    for filename in args.filenames:
        if filename not in excluded_filenames:
            with open(filename, "r") as f:
                for i, line in enumerate(f):
                    if "#PS-IGNORE":
                        continue
                    rule = trufflehog_detect_secret_in_line(line, filename)
                    if not rule:
                        rule = pii_in_line(line, filename)
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
