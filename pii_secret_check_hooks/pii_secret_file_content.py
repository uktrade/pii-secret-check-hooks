import os
import argparse
import re
from rich.console import Console

from truffleHogRegexes.regexChecks import regexes as trufflehog_regexes
from truffleHog.truffleHog import (
    get_strings_of_set,
    BASE64_CHARS,
    HEX_CHARS,
    shannon_entropy,
)

from pii_secret_check_hooks.config import IGNORE_EXTENSIONS, PII_REGEX
from pii_secret_check_hooks.util import (
    get_regex_from_file,
    get_excluded_filenames,
)

console = Console()


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


def detect_pii_or_secret_in_line(line_to_check, custom_regex_list):
    for trufflehog_key, trufflehog_regex in trufflehog_regexes.items():
        if re.search(trufflehog_regex, line_to_check):
            return trufflehog_key

    if entropy_check(line_to_check):
        return "'entropy check failed'"

    for pii_key, pii_regex in PII_REGEX.items():
        try:
            if re.search(pii_regex, line_to_check.lower()):
                return pii_key
        except re.error as ex:
            console.print(
                f"PII regex error for {pii_key} regex: '{ex}",
                style="white on blue"
            )
            return None

    for custom_regex in custom_regex_list:
        regex_name = custom_regex
        if "=" in custom_regex:
            parts = custom_regex.split("=")
            regex_name = parts[0]
            custom_regex = parts[1]
        try:
            if re.search(custom_regex, line_to_check.lower()):
                return f"'{regex_name}'"
        except re.error as ex:
            console.print(
                f"Custom regex error for '{custom_regex}' regex: '{ex}'",
                style="white on blue"
            )
            return None

    return None


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Files to check",
    )
    parser.add_argument(
        "exclude",
        nargs="?",
        default=".pii-secret-exclude",
        help="Exclude file path",
    )
    parser.add_argument(
        "regex_file",
        nargs="?",
        default=".pii-custom-regex",
        help="File with custom regex (one per line)",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)
    custom_regex_list = get_regex_from_file(args.regex_file)

    # Exclude custom regex file
    excluded_filenames.append(args.regex_file)

    exit_code = 0

    for filename in args.filenames:
        _, file_extension = os.path.splitext(filename)
        if file_extension in IGNORE_EXTENSIONS:
            console.print(
                f"{filename} ignoring file as extension ignored by default",
                style="white on blue"
            )
        else:
            if filename not in excluded_filenames:
                try:
                    with open(filename, "r") as f:
                        try:
                            for i, line in enumerate(f):
                                if "#PS-IGNORE" in line:
                                    continue

                                rule = detect_pii_or_secret_in_line(line, custom_regex_list)

                                if rule:
                                    console.print(
                                        f"{filename} line {i + 1}. String matching rule found: {rule}",
                                        style="white on blue"
                                    )
                                    exit_code = 1
                        except Exception as ex:
                            # These errors can potentially be ignored
                            console.print(
                                f"{filename} error when attempting to parse file content, ex: '{ex}'.",
                                style="bold red"
                            )
                except EnvironmentError as ex:
                    # Error out of process if we cannot access file
                    console.print(
                        f"{filename} error when attempting to open file, ex: {ex}.",
                        style="bold red"
                    )
                    exit_code = 1

    return exit_code


if __name__ == "__main__":
    exit(main())
