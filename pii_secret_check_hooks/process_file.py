import logging
import hashlib
import json
from pathlib import Path

import os
import argparse
import spacy
from rich.console import Console
import en_core_web_sm

from pii_secret_check_hooks.config import (
    IGNORE_EXTENSIONS,
    NER_IGNORE,
    NER_EXCLUDE,
)
from pii_secret_check_hooks.util import (
    get_excluded_filenames,
    get_excluded_ner,
)

from pii_secret_check_hooks.util import (
    print_error,
    print_info,
    print_warning,
)

nlp = en_core_web_sm.load()

console = Console()


class LineUpdatedException(Exception):
    pass


class LineHashChangedException(Exception):
    pass


class FoundSensitiveException(Exception):
    pass


class BaseFileProcess:
    BUFF_SIZE = 65536

    def __init__(self, filename, excluded_file_list):
        self.excluded_file_list = excluded_file_list
        self.log_data = None

        # Load JSON file list
        log_file = Path(".pii-secret-hook/pii-secret-log")
        if log_file.is_file():
            self.log_data = json.load(log_file)

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


