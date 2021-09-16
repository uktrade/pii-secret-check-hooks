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

nlp = en_core_web_sm.load()

from pii_secret_check_hooks.check_file.base import (
    LineUpdatedException,
    LineHashChangedException,
    FoundSensitiveException,
    CheckFileBase,
)


class CheckForNER(CheckFileBase):
    replace_lines = []
    current_line_num = 0
    current_line = None
    exclude_regex = re.compile("(.*#PS-IGNORE) ([a-f0-9]{40})(.*)")

    def __init__(self, excluded_file_list, excluded_entity_list, filename, interactive=True):
        self.excluded_entity_list = excluded_entity_list
        self.interactive = interactive
        self.filename = filename
        super(CheckForNER, self).__init__(excluded_file_list)

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


        matched = self.exclude_regex.findall(line)

        if len(matched) == 0:
            return True

        line_no_hash = matched[0][0] + matched[0][2]
        current_hash = matched[0][1]
        line_sha1.update(
            line_no_hash.encode('utf-8'),
        )

        if line_sha1.hexdigest() == current_hash:
            return False

        return True

    def update_line_hash(self):
        line_sha1 = hashlib.sha1()
        matched = self.exclude_regex.findall(self.current_line)

        if len(matched) == 0:
            # No hash
            line_no_hash = self.current_line
            new_hash = line_sha1.update(
                self.current_line.encode('utf-8'),
            ).hexdigest()
        else:
            line_no_hash = matched[0][0] + matched[0][2]
            new_hash = line_sha1.update(
                line_no_hash.encode('utf-8'),
            ).hexdigest()

        index = line_no_hash.index("#PS-IGNORE")
        return line_no_hash[:index] + ' ' + new_hash + line_no_hash[index:]

    def process_from_line(self, file_object):
        for i, line in enumerate(file_object):
            self.current_line = line
            self.current_line_num = i + 1

            if "#PS-IGNORE" in line:
                if not self.line_has_changed():
                    continue
                elif self.interactive:
                    print_warning(
                        line
                    )
                    print_error(
                        f"{filename} line marked for exclusion. Please confirm by "
                        f"typing 'y' that there is no sensitive information present",
                    )
                    confirmation = input()
                    if confirmation == "y":
                        self.replace_lines.append(
                            (
                                i + 1,
                                self.add_line_hash()
                            )
                        )
                else:
                    raise LineHashChangedException()
            else:
                if self.detect_named_entities(
                    line,
                    self.current_line_num,
                    self.excluded_entity_list
                ):
                    raise FoundSensitiveException()

    def process_file(self, filename):
        if filename not in self.excluded_file_list:
            if self.file_changed(filename):
                with open(filename, "r+") as f:
                    try:
                        print_info(
                            f"{filename} checking for sensitive data",
                        )
                        self.process_from_line(f, filename)
                    except LineHashChangedException as ex:
                        # These errors can potentially be ignored
                        print_error(
                            f"{filename} line has changed and has not been confirmed"
                            f" as non sensitive. Existing file processing.",
                        )
                        raise LineHashChangedException()
                    except Exception as ex:
                        # These errors can potentially be ignored
                        print_error(
                            f"{filename} error when attempting to parse file content, ex: '{ex}'.",
                        )

                    # Create file hash
                    file_content = f.read()
                    file_sha1 = hashlib.sha1()
                    file_sha1.update(file_content)

                    # Write file log
                    self.log_data[filename].hash = file_sha1

                    log_file = open(".pii-secret-log", "a")
                    log_file.write(self.log_data)
                    log_file.close()

                # Write changes to file
                if len(self.replace_lines) > 0:
                    f.seek(0)
                    for i, line in enumerate(f):
                        for replace_line in self.replace_lines:
                            if i == replace_line[0]:
                                pass
