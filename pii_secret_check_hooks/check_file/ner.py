import pathlib
import tokenize

import spacy
import en_core_web_sm

from pii_secret_check_hooks.config import (
    LINE_MARKER,
    NER_IGNORE,
    NER_EXCLUDE,
)

from pii_secret_check_hooks.util import (
    print_info,
    print_warning,
)

from pii_secret_check_hooks.check_file.base_content_check import (
    CheckFileBase,
)


nlp = en_core_web_sm.load()
PYTHON_CODE_SUFFIX = ".py"

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
        allow_changed_lines=False,
        excluded_file_list=None,
        excluded_ner_entity_list=None,
        ner_output_file=None,
    ):
        self.excluded_file_list = [] if excluded_file_list is None else excluded_file_list
        self.excluded_ners = set(excluded_ner_entity_list or [])
        self.ner_output_file = ner_output_file
        self.entity_list = []

        super(CheckForNER, self).__init__(
            check_name="ner",
            allow_changed_lines=allow_changed_lines,
            excluded_file_list=self.excluded_file_list,
        )

    def entity_is_suspicious(self, entity):
        """True if this NER looks suspicious."""
        return not (
            (entity.label_ in NER_IGNORE)
            or (entity.text in NER_EXCLUDE)
            or (entity.text in self.excluded_ners)
            or (entity.text.lower().strip() in self.excluded_ners)
        )

    def line_has_issue(self, line) -> bool:
        doc = nlp(line)
        found_issue = False
        if doc.ents:
            for ent in doc.ents:
                if self.entity_is_suspicious(ent):
                    print_warning(
                        f"Line {self.current_line_num}. please check '{ent.text}' - {ent.label_} - {str(spacy.explain(ent.label_))}",
                    )
                    if ent.text not in self.entity_list:
                        self.entity_list.append(ent.text)
                    found_issue = True

        return found_issue

    def _issue_found_in_python_content(self, file_object) -> bool:
        found_issue = False

        # The Python source code token and a Spacy named entity.
        for token, entity in ner_python_scanner(file_object):
            lineno, _ = token.start

            if LINE_MARKER in token.line and self.allow_changed_lines:
                continue

            if not self.entity_is_suspicious(entity):
                continue

            found_issue = True
            print_warning(
                f"Line {lineno}. please check '{entity}' - {entity.label_}"
                f" - {spacy.explain(entity.label_)}"
            )
            if entity.text not in self.entity_list:
                self.entity_list.append(entity.text)

        return found_issue

    def _issue_found_in_file_content(self, file_object, filename) -> bool:
        path = pathlib.Path(filename)

        if path.suffix.lower() == PYTHON_CODE_SUFFIX:
            return self._issue_found_in_python_content(file_object)

        return super()._issue_found_in_file_content(file_object, filename)

    def after_run(self) -> None:
        if self.ner_output_file:
            self._generate_ner_file()
        else:
            print_info("No NER output file provided")

    def _generate_ner_file(self) -> None:
        # The pre-commit hook invokes this program multiple times if there are
        # many files. Use append mode so that we don't overwrite output from
        # other invocations. The user is responsible for deleting the file
        # between runs.
        if not self.entity_list:
            return

        with open(self.ner_output_file, "a") as exclude_file:
            for entity in self.entity_list:
                exclude_file.write(f"{entity}\n")


def ner_python_scanner(fh):
    """Yield a (token, entity) pair for each NER found in a Python source file.

    Only Python strings and comments are scanned, other source text is ignored.
    """
    interesting_types = (tokenize.COMMENT, tokenize.STRING)

    for tok in tokenize.generate_tokens(fh.readline):
        if tok.type in interesting_types:
            # Normalize Python comments and whitespace inside strings.
            value = tok.string.strip().lstrip('#')
            value = " ".join(value.split())

            for ent in nlp(value).ents:
                yield tok, ent
