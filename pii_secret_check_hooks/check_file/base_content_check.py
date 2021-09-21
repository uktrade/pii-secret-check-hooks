import os
import hashlib
import json
from abc import ABC, abstractmethod
from pathlib import Path

from pii_secret_check_hooks.config import (
    LINE_MARKER,
    IGNORE_EXTENSIONS,
)

from pii_secret_check_hooks.util import (
    print_error,
    print_info,
    print_warning,
)


class FoundSensitiveException(Exception):
    pass


class NoExcludeFilePassedException(Exception):
    pass


class LineHashChangedException(Exception):
    pass


class CheckFileBase(ABC):
    current_file = None
    BUFF_SIZE = 65536

    def __init__(
        self,
        check_name,
        excluded_file_list,
        exclude_output_file=None,
    ):
        self.excluded_file_list = excluded_file_list
        self.exclude_output_file = exclude_output_file
        self.log_path = f".pii-secret-hook/{check_name}/pii-secret-log"
        self.log_data = self._get_empty_log()

        if self.log_path:
            Path(f".pii-secret-hook/{check_name}").mkdir(parents=True, exist_ok=True)

            with open(self.log_path, 'a+') as json_file:
                try:
                    self.log_data = json.load(json_file)
                except json.decoder.JSONDecodeError:
                    self.log_data = self._get_empty_log()

        super().__init__()

    def _get_empty_log(self):
        return {
            "files": {},
            "excluded_lines": {},
        }

    def _create_file_hash(self, file_obj) -> str:
        file_obj.seek(0)
        content = file_obj.read()

        sha1 = hashlib.sha1()
        sha1.update(content.encode("utf-8"))

        # Reset for other callers
        file_obj.seek(0)

        return sha1.hexdigest()

    def _file_extension_excluded(self, filename) -> bool:
        _, file_extension = os.path.splitext(filename)
        if file_extension in IGNORE_EXTENSIONS:
            return True

        return False

    def _file_excluded(self, filename) -> bool:
        if filename in self.excluded_file_list:
            return True

        return False

    def _file_changed(self, file_obj) -> bool:
        file_hash = self._create_file_hash(file_obj)
        if self.current_file in self.log_data["files"]:
            existing_file_hash = self.log_data["files"][self.current_file]["hash"]
            if existing_file_hash == file_hash:
                return False

        return True

    # Check to see if line (without hash) matches hash
    def _line_has_changed(self, line_num, line) -> bool:
        if self.current_file in self.log_data["excluded_lines"]:
            file_info = self.log_data["excluded_lines"][self.current_file]
            if file_info["line"] == line_num:
                line_sha1 = hashlib.sha1()
                line_sha1.update(
                    line.encode("utf-8"),
                )
                if file_info["hash"] == line_sha1.hexdigest():
                    return False

        return True

    def _update_line_hash(self, line_num, line) -> None:
        line_sha1 = hashlib.sha1()
        line_sha1.update(
            line.encode('utf-8'),
        )

        if self.current_file in self.log_data["excluded_lines"]:
            self.log_data["excluded_lines"][self.current_file] = {
                "hash": line_sha1.hexdigest(),
                "line": line_num,
            }
        else:
            self.log_data["excluded_lines"][self.current_file]["line"] = line_num
            self.log_data["excluded_lines"][self.current_file]["hash"] = line_sha1.hexdigest()

    def _process_file(self, filename) -> bool:
        found_issue = False
        if filename not in self.excluded_file_list:
            self.current_file = filename
            with open(filename, "r+") as f:
                if self._file_changed(f):
                    print_info(
                        f"{filename} checking for sensitive data",
                    )
                    found_issue = self._process_file_content(f)

                    if not found_issue:
                        # If no issue was found, create and save file hash
                        file_hash = self._create_file_hash(f)

                        # Set file entry in file log
                        if self.current_file not in self.log_data["files"]:
                            self.log_data["files"][self.current_file] = {
                                "hash": ""
                            }

                        self.log_data["files"][self.current_file]["hash"] = file_hash

        return found_issue

    def process_files(self, filenames) -> bool:
        found_issues = False
        for filename in filenames:
            if not self._file_extension_excluded(filename):
                if not self._file_excluded(filename):
                    if self._process_file(filename):
                        found_issues = True

        log_file = open(self.log_path, "w")
        log_file.write(json.dumps(self.log_data))
        log_file.close()

        return found_issues

    def _process_file_content(self, file_object) -> bool:
        found_issue = False
        for i, line in enumerate(file_object):
            self.current_line_num = i + 1
            if LINE_MARKER in line:
                if not self._line_has_changed(i, line):
                    continue
                elif self.interactive:
                    print_warning(
                        line.strip()
                    )
                    print_info(
                        "Line marked for exclusion. Please type 'y' to confirm "
                        "that there is no sensitive information present",
                    )
                    confirmation = input()
                    if confirmation == "y":
                        self._update_line_hash(i + 1, line)
                    else:
                        print_info(line)
                        print_error(
                            f"Line has been updated since last check",
                        )
                        found_issue = True
                else:
                    print_info(line.strip())
                    print_error(
                        f"Line has been updated since last check",
                    )
                    found_issue = True
            else:
                if self.process_line(line):
                    found_issue = True

        return found_issue

    @abstractmethod
    def process_line(self, line):
        raise NotImplementedError()
