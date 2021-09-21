import re
from rich.console import Console

from pii_secret_check_hooks.config import FILENAME_REGEX

console = Console()


def _detect_match_against_filename(filename, filename_regex):
    for regex in filename_regex:
        if re.search(regex, filename):
            return regex


def check_file_names(filenames, excluded_filenames=[]):
    found_issue = False
    for filename in filenames:
        if filename not in excluded_filenames:
            match = _detect_match_against_filename(filename, FILENAME_REGEX)
            if match:
                found_issue = True
                console.print(
                    f"{filename} may contain sensitive information due to the file type",
                    style="bold red",
                    soft_wrap=True,
                )

    return found_issue
