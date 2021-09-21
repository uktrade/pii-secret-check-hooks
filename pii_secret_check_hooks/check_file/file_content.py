import re
import en_core_web_sm

from rich.console import Console

from truffleHogRegexes.regexChecks import regexes as trufflehog_regexes
from truffleHog.truffleHog import (
    get_strings_of_set,
    BASE64_CHARS,
    HEX_CHARS,
    shannon_entropy,
)

from pii_secret_check_hooks.config import PII_REGEX

from pii_secret_check_hooks.check_file.base_content_check import (
    CheckFileBase,
)


nlp = en_core_web_sm.load()


class LineUpdatedException(Exception):
    pass


class NoExcludeFilePassedException(Exception):
    pass


console = Console()


class CheckFileContent(CheckFileBase):
    replace_lines = []
    current_line_num = 0
    current_line = None

    def __init__(
        self,
        excluded_file_list,
        custom_regex_list,
        exclude_output_file=None,
        interactive=True,
    ):
        self.custom_regex_list = custom_regex_list
        self.interactive = interactive

        super(CheckFileContent, self).__init__(
            "file_content",
            excluded_file_list,
            exclude_output_file,
        )

    def _entropy_check(self, line):
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

    def _trufflehog_check(self, line):
        for trufflehog_key, trufflehog_regex in trufflehog_regexes.items():
            if re.search(trufflehog_regex, line):
                return trufflehog_key

        return None

    def _pii_regex(self, line):
        for pii_key, pii_regex in PII_REGEX.items():
            try:
                if re.search(pii_regex, line.lower()):
                    return pii_key
            except re.error as ex:
                console.print(
                    f"PII regex error for {pii_key} regex: '{ex}",
                    style="white on blue",
                    soft_wrap=True,
                )
                return None

    def _custom_regex_checks(self, line):
        for custom_regex in self.custom_regex_list:
            regex_name = custom_regex
            if "=" in custom_regex:
                parts = custom_regex.split("=")
                regex_name = parts[0]
                custom_regex = parts[1]
            try:
                if re.search(custom_regex, line.lower()):
                    return f"'{regex_name}'"
            except re.error as ex:
                console.print(
                    f"Custom regex error for '{custom_regex}' regex: '{ex}'",
                    style="white on blue",
                    soft_wrap=True,
                )
                return None

    def process_line(self, line):
        trufflehog_check = self._trufflehog_check(line)
        if trufflehog_check:
            return trufflehog_check

        if self._entropy_check(line):
            return "'entropy check failed'"

        pii_check = self._pii_regex(line)
        if pii_check:
            return self._pii_regex(line)

        custom_regex_check = self._custom_regex_checks(line)
        if custom_regex_check:
            return custom_regex_check

        return None
