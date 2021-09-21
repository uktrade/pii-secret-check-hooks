import os
import hashlib
import json
from abc import ABC, abstractmethod

from pii_secret_check_hooks.config import (
    LINE_MARKER,
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
        excluded_file_list,
        exclude_output_file=None,
        log_path=".pii-secret-hook/pii-secret-log",
    ):
        self.excluded_file_list = excluded_file_list
        self.exclude_output_file = exclude_output_file
        self.log_path = log_path
        self.log_data = {}

        if self.log_path:
            with open(self.log_path, 'r+') as json_file:
                self.log_data = json.load(json_file)

        super().__init__()

    def _create_file_hash(self, file_obj) -> str:
        file_obj.seek(0)
        content = file_obj.read()

        sha1 = hashlib.sha1()
        sha1.update(content.encode("utf-8"))

        # Reset for other callers
        file_obj.seek(0)

        return sha1.hexdigest()

    def _file_extension_excluded(self, filename, ignore_extensions) -> bool:
        _, file_extension = os.path.splitext(filename)
        if file_extension in ignore_extensions:
            return True

        return False

    def _file_excluded(self, filename, exclude_list) -> bool:
        if filename in exclude_list:
            return True

        return False

    def _file_changed(self, file_obj) -> bool:
        if self.current_file in self.log_data["files"]:
            file_hash = self.log_data["files"][self.current_file]["hash"]
            if file_hash == self._create_file_hash(file_obj):
                return False

        return True

    # Check to see if line (without hash) matches hash
    def _line_has_changed(self, line_num, line):
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

    def _update_line_hash(self, line_num, line):
        line_sha1 = hashlib.sha1()
        line_sha1.update(
            line.encode('utf-8'),
        )

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
                    # Trap exceptions to this func call in enclosing logic
                    found_issue = self._process_file_content(f)

                    # Create file hash
                    file_hash = self._create_file_hash(f)

                    # Set file entry in file log
                    self.log_data[self.current_file].hash = file_hash

        return found_issue

    def process_files(self, filenames) -> bool:
        found_issues = False
        for filename in filenames:
            if not self._file_extension_excluded():
                if not self._file_excluded():
                    if self._process_file(filename):
                        found_issues = True

        log_file = open(self.log_path, "w")  # w+ ?
        log_file.write(self.log_data)
        log_file.close()

        return found_issues

    def _process_file_content(self, file_object):
        for i, line in enumerate(file_object):
            if LINE_MARKER in line:
                if not self._line_has_changed(i, line):
                    continue
                elif self.interactive:
                    print_warning(
                        line
                    )
                    print_error(
                        f"{self.current_file} line marked for exclusion. Please confirm by "
                        f"typing 'y' that there is no sensitive information present",
                    )
                    confirmation = input()
                    if confirmation == "y":
                        self._update_line_hash(i + 1, line)
                    else:
                        raise LineHashChangedException()
                else:
                    raise LineHashChangedException()
            else:
                if self.process_line(line):
                    raise FoundSensitiveException()

    @abstractmethod
    def process_line(self, line):
        raise NotImplementedError()
