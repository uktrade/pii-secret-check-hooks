import os
import hashlib
import json
from json import load as load_json
from abc import ABC, abstractmethod
from pathlib import Path

from pii_secret_check_hooks.config import (
    LINE_MARKER,
    IGNORE_EXTENSIONS,
)

from pii_secret_check_hooks.util import (
    print_error,
    print_info,
    print_debug,
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
        interactive=False,
        excluded_file_list=[],
    ):
        self.interactive = interactive
        self.excluded_file_list = excluded_file_list
        self.log_path = f".pii-secret-hook/{check_name}/pii-secret-log"
        self.log_data = self._get_empty_log()
        self.debug = True

        if self.log_path:
            Path(f".pii-secret-hook/{check_name}").mkdir(parents=True, exist_ok=True)

            with open(self.log_path, 'r') as json_file:
                try:
                    self.log_data = load_json(json_file)
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

    def _issue_found_in_file(self, filename) -> bool:
        try:
            found_issue = False
            if filename not in self.excluded_file_list:
                self.current_file = filename
                with open(filename, "r+") as f:
                    print_info(
                        f"{filename}",
                    )
                    if self._file_changed(f):
                        if self._issue_found_in_file_content(f):
                            return True
                        else:
                            # If no issue was found, create and save file hash
                            file_hash = self._create_file_hash(f)

                            # Set file entry in file log
                            if self.current_file not in self.log_data["files"]:
                                self.log_data["files"][self.current_file] = {
                                    "hash": ""
                                }

                            self.log_data["files"][self.current_file]["hash"] = file_hash

            return found_issue
        except Exception as ex:
            print_error(
                f"An exception occurred processing this file, ex: {ex}"
            )
            return True

    def _write_log(self):
        log_file = open(self.log_path, "w")
        log_file.write(json.dumps(self.log_data))
        log_file.close()

    def process_files(self, filenames) -> bool:
        found_issues = False

        for filename in filenames:
            if not self._file_extension_excluded(filename):
                if not self._file_excluded(filename):
                    if self._issue_found_in_file(filename):
                        found_issues = True

        self._write_log()
        self.after_run()

        return found_issues

    def _issue_found_in_file_content(self, file_object) -> bool:
        found_issue = False
        for i, line in enumerate(file_object):
            self.current_line_num = i + 1
            if LINE_MARKER in line:
                if not self._line_has_changed(i, line):
                    continue
                elif self.interactive:
                    print_warning(
                        f"Line {self.current_line_num}. {line.strip()}"
                    )
                    print_info(
                        "Line marked for exclusion. Please type 'y' to confirm "
                        "that there is no sensitive information present",
                    )
                    confirmation = input()
                    if confirmation == "y":
                        self._update_line_hash(i + 1, line)
                    else:
                        print_error(
                            f"Line has been updated since last check",
                        )
                        found_issue = True
                else:
                    # If we're not in interactive mode,
                    # we can't get a confirmation on the
                    # status of sensitive info
                    print_warning(
                        f"Line {self.current_line_num}. {line.strip()}"
                    )
                    print_error(
                        "Line marked for exclusion but it has changed since it "
                        "was last checked. Please manually check it does not "
                        "contain sensitive information",
                    )
            else:
                if self.line_has_issue(line):
                    found_issue = True

        return found_issue

    @abstractmethod
    def line_has_issue(self, line):
        raise NotImplementedError()

    """Optional post process logic"""
    @abstractmethod
    def after_run(self):
        raise NotImplementedError()
