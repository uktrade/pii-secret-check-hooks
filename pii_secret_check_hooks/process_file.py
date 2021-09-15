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

nlp = en_core_web_sm.load()

console = Console()


class BaseFileProcess:
    BUFF_SIZE = 65536

    def __init__(self, filename, excluded_file_list):
        self.excluded_file_list = excluded_file_list
        self.log_data = None

        # Load JSON file list
        log_file = Path(".pii-secret-log")
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


class LineUpdatedException(Exception):
    pass


class FoundSensitiveException(Exception):
    pass


class NERFileProcess(BaseFileProcess):
    current_line_num = 0
    current_line = None

    def __init__(self, excluded_file_list, excluded_entity_list):
        self.excluded_entity_list = excluded_entity_list
        super(BaseFileProcess, self).__init__(excluded_file_list)

    def detect_named_entities(self, line, line_num, excluded_entities):
        doc = nlp(line)
        found_issue = False
        if doc.ents:
            for ent in doc.ents:
                if (
                    ent.label_ not in NER_IGNORE and
                    ent.text not in NER_EXCLUDE and
                    ent.text.lower() not in excluded_entities
                ):
                    console.print(
                        f"Line {line_num}, please check '{ent.text}' - {ent.label_} - {str(spacy.explain(ent.label_))}",
                        style="white on blue",
                        soft_wrap=True,
                    )
                    found_issue = True

        return found_issue

    # Check to see if line (without hash) matches hash
    def line_has_changed(self, line):
        line_sha1 = hashlib.sha1()

        line_parts = line.split("#PS-IGNORE")
        hash_parts = line_parts[1].split(" ")

        if len(hash_parts) > 0:
            line_hash = hash_parts[0]
            line_sha1.update(line.replace(line_hash, ""))

            if line_sha1 == line_hash:
                return False

        return True

    def update_line_hash(self):
        line_sha1 = hashlib.sha1()
        line_sha1.update(self.current_line)

        index = self.current_line.index("#PS-IGNORE")
        return self.current_line[:index] + ' ' + line_sha1 + self.current_line[index:]

    def process_file(self, filename):
        # Check to see if file is unchanged since last check
        if self.file_changed(filename):
            with open(filename, "r") as f:
                try:
                    console.print(
                        f"{filename} checking for sensitive data",
                        style="white on blue",
                        soft_wrap=True,
                    )
                    for i, line in enumerate(f):
                        self.current_line = line
                        self.current_line_num = i + 1

                        if "#PS-IGNORE" in line:
                            if not self.line_has_changed():
                                continue
                            else:
                                raise LineUpdatedException()
                        else:
                            if self.detect_named_entities(
                                line,
                                self.current_line_num,
                                self.excluded_entity_list
                            ):
                                raise FoundSensitiveException()
                except Exception as ex:
                    # These errors can potentially be ignored
                    console.print(
                        f"{filename} error when attempting to parse file content, ex: '{ex}'.",
                        style="bold red",
                        soft_wrap=True,
                    )


















def check_if_excluded():
    pass


def check_if_line_updated():
    pass
