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


def detected_named_entities(line, line_num, excluded_entities):
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


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Files to check",
    )
    parser.add_argument(
        "exclude",
        nargs="?",
        default=".pii-secret-exclude",
        help="Exclude file path",
    )
    parser.add_argument(
        "ner_exclude",
        nargs="?",
        default=".pii-custom-ner-exclude",
        help="Named Entity Recognition exclude file path. One per line.",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)
    excluded_entities = get_excluded_ner(args.ner_exclude)

    # Exclude custom regex file
    excluded_filenames.append(args.exclude)

    exit_code = 0

    console.print(
        "Using spaCY NER (https://spacy.io/) for PII checks",
        style="white on blue",
        soft_wrap=True,
    )

    for filename in args.filenames:
        _, file_extension = os.path.splitext(filename)
        if file_extension in IGNORE_EXTENSIONS:
            pass
            # console.print(
            #     f"{filename} ignoring file as extension is ignored by default",
            #     style="white on blue"
            # )
        else:
            if filename not in excluded_filenames:
                try:
                    with open(filename, "r") as f:
                        try:
                            console.print(
                                f"{filename} checking for PII",
                                style="white on blue",
                                soft_wrap=True,
                            )
                            for i, line in enumerate(f):
                                if "#PS-IGNORE" in line:
                                    continue

                                if detected_named_entities(line, (i + 1), excluded_entities):
                                    exit_code = 1

                        except Exception as ex:
                            # These errors can potentially be ignored
                            console.print(
                                f"{filename} error when attempting to parse file content, ex: '{ex}'.",
                                style="bold red",
                                soft_wrap=True,
                            )
                except EnvironmentError as ex:
                    # Error out of process if we cannot access file
                    console.print(
                        f"{filename} error when attempting to open file, ex: {ex}.",
                        style="bold red",
                        soft_wrap=True,
                    )
                    exit_code = 1

    return exit_code


if __name__ == "__main__":
    exit(main())
