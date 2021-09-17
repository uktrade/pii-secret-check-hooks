import os
import abc
import hashlib
import json

from pii_secret_check_hooks.util import (
    print_error,
    print_info,
    print_warning,
)


class FoundSensitiveException(Exception):
    pass


class CheckFileBase:
    __metaclass__ = abc.ABCMeta

    current_file = None
    BUFF_SIZE = 65536

    def __init__(
        self,
        excluded_file_list,
        log_path=".pii-secret-hook/pii-secret-log",
    ):
        self.excluded_file_list = excluded_file_list
        self.log_path = log_path
        self.log_data = None

        with open(self.log_path, 'r+') as json_file:
            self.log_data = json.load(json_file)

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

    def process_files(self, filenames) -> bool:
        found_issues = False
        for filename in filenames:
            if not self._file_extension_excluded():
                if not self._file_excluded():
                    if self._process_file(filename):
                        found_issues = True

        self._write_log()
        return found_issues

    def _write_log(self) -> None:
        log_file = open(self.log_path, "w")  # w+ ?
        log_file.write(self.log_data)
        log_file.close()

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
                    found_issue = self.process_file_content(f)

                    # Create file hash
                    file_hash = self._create_file_hash(f)

                    # Set file entry in file log
                    self.log_data[self.current_file].hash = file_hash

        return found_issue

    @abc.abstractmethod
    def process_file_content(self, file_object) -> bool:
        """Should return false if content fails checks"""
        return False
