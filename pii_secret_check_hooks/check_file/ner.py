import re
import hashlib
import spacy
import en_core_web_sm

from pii_secret_check_hooks.config import (
    NER_IGNORE,
    NER_EXCLUDE,
)

from pii_secret_check_hooks.util import (
    print_error,
    print_info,
    print_warning,
)

from pii_secret_check_hooks.check_file.base import (
    FoundSensitiveException,
    CheckFileBase,
)

nlp = en_core_web_sm.load()


class LineUpdatedException(Exception):
    pass


class LineHashChangedException(Exception):
    pass


class CheckForNER(CheckFileBase):
    replace_lines = []
    current_line_num = 0
    current_line = None

    def __init__(
        self,
        filename,
        excluded_file_list,
        excluded_entity_list,
        interactive=True,
        log_path=".pii-secret-hook/pii-secret-log",
    ):
        self.excluded_entity_list = excluded_entity_list
        self.interactive = interactive
        self.filename = filename
        super(CheckForNER, self).__init__(filename, excluded_file_list, log_path)

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
                    print_info(
                        f"Line {line_num}, please check '{ent.text}' - {ent.label_} - {str(spacy.explain(ent.label_))}",
                    )
                    found_issue = True

        return found_issue

    # Check to see if line (without hash) matches hash
    def line_has_changed(self, line_num, line):
        if self.filename in self.log_data["excluded_lines"]:
            file_info = self.log_data["excluded_lines"][self.filename]
            if file_info["line"] == line_num:
                line_sha1 = hashlib.sha1()
                line_sha1.update(
                    line.encode('utf-8'),
                )
                if file_info["hash"] == line_sha1.hexdigest():
                    return False

        return True

    def update_line_hash(self, line_num, line):
        line_sha1 = hashlib.sha1()
        line_sha1.update(
            line.encode('utf-8'),
        )

        self.log_data["excluded_lines"][self.filename]["line"] = line_num
        self.log_data["excluded_lines"][self.filename]["hash"] = line_sha1.hexdigest()

    def process_file_content(self, file_object):
        for i, line in enumerate(file_object):
            if "#PS-IGNORE" in line:
                if not self.line_has_changed(i, line):
                    continue
                elif self.interactive:
                    print_warning(
                        line
                    )
                    print_error(
                        f"{self.filename} line marked for exclusion. Please confirm by "
                        f"typing 'y' that there is no sensitive information present",
                    )
                    confirmation = input()
                    if confirmation == "y":
                        self.update_line_hash(i + 1, line)
                    else:
                        raise LineHashChangedException()
                else:
                    raise LineHashChangedException()
            else:
                if self.detect_named_entities(
                    line,
                    self.current_line_num,
                    self.excluded_entity_list
                ):
                    raise FoundSensitiveException()

    def process_file(self):
        if self.filename not in self.excluded_file_list:
            if self.file_changed(self.filename):
                with open(self.filename, "r+") as f:
                    try:
                        print_info(
                            f"{self.filename} checking for sensitive data",
                        )
                        self.process_file_content(f)
                    except LineHashChangedException as ex:
                        # These errors can potentially be ignored
                        print_error(
                            f"{self.filename} line has changed and has not been confirmed"
                            f" as non sensitive. Existing file processing.",
                        )
                        raise LineHashChangedException()
                    except Exception as ex:
                        # These errors can potentially be ignored
                        print_error(
                            f"{self.filename} error when attempting to parse file content, ex: '{ex}'.",
                        )

                self.write_log(f)
