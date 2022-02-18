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
from pii_secret_check_hooks.util import (
    print_error,
    print_warning,
)

nlp = en_core_web_sm.load()


class LineUpdatedException(Exception):
    pass


console = Console()


class CheckFileContent(CheckFileBase):
    replace_lines = []
    current_line_num = 0
    current_line = None

    def __init__(
        self,
        allow_changed_lines=False,
        excluded_file_list=None,
        custom_regex_list=None,
    ):
        self.excluded_file_list = [] if excluded_file_list is None else excluded_file_list
        self.custom_regex_list = [] if custom_regex_list is None else custom_regex_list
        super(CheckFileContent, self).__init__(
            check_name="file_content",
            allow_changed_lines=allow_changed_lines,
            excluded_file_list=self.excluded_file_list,
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
                print_error(
                    f"PII regex error for {pii_key} regex: '{ex}",
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
                print_error(
                    f"Custom regex error for {custom_regex} regex: '{ex}'",
                )
                return None

    def line_has_issue(self, line) -> bool:
        trufflehog_check = self._trufflehog_check(line)
        if trufflehog_check:
            print_warning(
                f"Line {self.current_line_num}. {trufflehog_check} check failed",
            )
            return True

        if self._entropy_check(line):
            print_warning(
                f"Line {self.current_line_num}. entropy check failed",
            )
            return True

        pii_check_result = self._pii_regex(line)
        if pii_check_result:
            print_warning(
                f"Line {self.current_line_num}. {pii_check_result} check failed",
            )
            return True

        custom_regex_check = self._custom_regex_checks(line)
        if custom_regex_check:
            print_warning(
                f"Line {self.current_line_num}. {custom_regex_check} check failed",
            )
            return True

        return False

    def after_run(self) -> None:
        pass
