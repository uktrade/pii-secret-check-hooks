import spacy
import en_core_web_sm

from pii_secret_check_hooks.config import (
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
        interactive=False,
        excluded_file_list=[],
        excluded_ner_entity_list=[],
        exclude_output_file=None,
    ):
        self.excluded_ner_entity_list = excluded_ner_entity_list
        self.exclude_output_file = exclude_output_file
        self.entity_list = []

        super(CheckForNER, self).__init__(
            "ner",
            interactive,
            excluded_file_list,
        )

    def line_has_issue(self, line) -> bool:
        doc = nlp(line)
        found_issue = False
        if doc.ents:
            for ent in doc.ents:
                if (
                    ent.label_ not in NER_IGNORE and
                    ent.text not in NER_EXCLUDE and
                    ent.text.lower() not in self.excluded_ner_entity_list
                ):
                    print_warning(
                        f"Line {self.current_line_num}, please check '{ent.text}' - {ent.label_} - {str(spacy.explain(ent.label_))}",
                    )
                    self.entity_list.append(ent.text)
                    found_issue = True

        return found_issue

    def after_run(self) -> None:
        if self.exclude_output_file:
            self._generate_exclude_file()
        else:
            print_info("No exclude file provided")

    def _generate_exclude_file(self) -> None:
        if not self.exclude_output_file:
            raise NoExcludeFilePassedException()

        print_info(
            f"Outputting NER results to exclude file {self.exclude_output_file}",
        )
        with open(self.exclude_output_file, "w") as exclude_file:
            for entity in self.entity_list:
                exclude_file.write(f"{entity}\n")
