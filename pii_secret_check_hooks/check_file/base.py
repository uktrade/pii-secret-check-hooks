import hashlib
import json
from pathlib import Path


class FoundSensitiveException(Exception):
    pass


class CheckFileBase:
    BUFF_SIZE = 65536

    def __init__(
        self,
        filename,
        excluded_file_list,
        log_path=".pii-secret-hook/pii-secret-log",
    ):
        self.filename = filename
        self.excluded_file_list = excluded_file_list
        self.log_path = log_path
        self.log_data = None

        with open(self.log_path, 'r+') as json_file:
            self.log_data = json.load(json_file)

    def create_hash(self, filename):
        sha1 = hashlib.sha1()

        with open(filename, 'rb') as f:
            while True:
                data = f.read(self.BUFF_SIZE)
                if not data:
                    break
                sha1.update(data)

        return sha1

    def file_changed(self, filename):
        if filename in self.log_data["files"]:
            if filename in self.log_data["files"]:
                file_hash = self.log_data["files"][filename][filename].hash = self.log_data["files"][filename][filename].hash

            if file_hash == self.create_hash(filename):
                return False

        return True

    def write_log(self, file_obj):
        # Create file hash
        file_obj.seek(0)
        file_content = file_obj.read()
        file_sha1 = hashlib.sha1()
        file_sha1.update(file_content)

        # Write file log
        self.log_data[self.filename].hash = file_sha1

        log_file = open(self.log_path, "w+")
        log_file.write(self.log_data)
        log_file.close()
