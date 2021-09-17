import re
import hashlib
import spacy
import en_core_web_sm

from pii_secret_check_hooks.config import (
    NER_IGNORE,
    NER_EXCLUDE,
    LINE_MARKER,
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


class NoExcludeFilePassedException(Exception):
    pass


class CheckForNER(CheckFileBase):
    replace_lines = []
    current_line_num = 0
    current_line = None

    def __init__(
        self,
        excluded_file_list,
        excluded_ner_entity_list,
        exclude_output_file=None,
        interactive=True,
        log_path=".pii-secret-hook/pii-secret-log",
    ):
        self.excluded_ner_entity_list = excluded_ner_entity_list
        self.exclude_output_file = exclude_output_file
        self.interactive = interactive
        self.entity_list = []
        super(CheckForNER, self).__init__(excluded_file_list, log_path)

    def _detect_named_entities(self, line, line_num):
        doc = nlp(line)
        found_issue = False
        if doc.ents:
            for ent in doc.ents:
                if (
                    ent.label_ not in NER_IGNORE and
                    ent.text not in NER_EXCLUDE and
                    ent.text.lower() not in self.excluded_ner_entity_list
                ):
                    print_info(
                        f"Line {line_num}, please check '{ent.text}' - {ent.label_} - {str(spacy.explain(ent.label_))}",
                    )
                    self.entity_list.append(ent.text)
                    found_issue = True

        return found_issue

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

    def generate_exclude_file(self):
        if not self.exclude_output_file:
            raise NoExcludeFilePassedException()

        exclude_file = open(self.exclude_output_file, "w")
        for entity in self.entity_list:
            exclude_file.write(f"{entity}\n")
        exclude_file.close()

    def process_file_content(self, file_object):
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
                if self._detect_named_entities(
                    line,
                    self.current_line_num,
                ):
                    raise FoundSensitiveException()
