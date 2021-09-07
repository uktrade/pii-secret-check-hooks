import logging
import argparse
import re

from truffleHogRegexes.regexChecks import regexes as trufflehog_regexes
from truffleHog.truffleHog import (
    get_strings_of_set,
    BASE64_CHARS,
    HEX_CHARS,
    shannon_entropy,
)

from pii_secret_check_hooks.config import pii_regex
from pii_secret_check_hooks.util import (
    get_regex_from_file,
    get_excluded_filenames,
)


def entropy_check(line):
    strings_found = []
    for word in line.split():
        base64_strings = get_strings_of_set(word, BASE64_CHARS)
        hex_strings = get_strings_of_set(word, HEX_CHARS)
        for string in base64_strings:
            b64_entropy = shannon_entropy(string, BASE64_CHARS)
            if b64_entropy > 4.5:
                strings_found.append(string)
        for string in hex_strings:
            hex_entropy = shannon_entropy(string, HEX_CHARS)
            if hex_entropy > 3:
                strings_found.append(string)

    return len(strings_found) > 0


def detect_pii_or_secret_in_line(line_to_check, custom_regex):
    for trufflehog_key, trufflehog_regex in trufflehog_regexes.items():
        if re.search(trufflehog_regex, line_to_check):
            return trufflehog_key

    if entropy_check(line_to_check):
        return "'entropy check failed'"

    for pii_key, regex in pii_regex.items():
        try:
            if re.search(regex, line_to_check):
                return pii_key
        except re.error as ex:
            logging.error(f"PII regex error for {pii_key} regex: '{ex}'")

    for custom_regex in custom_regex:
        try:
            if re.search(custom_regex, line_to_check):
                return regex
        except re.error as ex:
            logging.error(f"Custom regex error for '{custom_regex}' regex: '{ex}'")

    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("filenames", nargs="*", help="Files to check")
    parser.add_argument(
        "exclude",
        nargs=1,
        default=".pii-secret-exclude",
        help="Exclude file path",
    )
    parser.add_argument(
        "regex_file",
        nargs=1,
        default=".pii-custom-regex",
        help="File with custom regex (one per line)",
    )
    args = parser.parse_args(argv)
    exit_code = 0

    excluded_filenames = get_excluded_filenames(args.exclude[0])
    custom_regex = get_regex_from_file(args.regex_file[0])

    for filename in args.filenames:
        if filename not in excluded_filenames:
            with open(filename, "r") as f:
                for i, line in enumerate(f):
                    if "#PS-IGNORE" in line:
                        continue

                    rule = detect_pii_or_secret_in_line(line, custom_regex)

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
