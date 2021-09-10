import os
import argparse
import spacy
from rich.console import Console
import en_core_web_sm

from pii_secret_check_hooks.config import IGNORE_EXTENSIONS
from pii_secret_check_hooks.util import (
    get_excluded_filenames,
)

nlp = en_core_web_sm.load()

console = Console()


def detected_named_entities(line):
    doc = nlp(line)
    if doc.ents:
        for ent in doc.ents:
            console.print(
                "Found named entity in line, please check for PII "
                f"'{ent.text}' - {str(ent.start_char)} - "
                f"{str(ent.end_char)} - {ent.label_} - {str(spacy.explain(ent.label_))}",
                style="bold blue",
            )
        return True

    return False


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
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)

    # Exclude custom regex file
    excluded_filenames.append(args.exclude)

    exit_code = 0

    console.print(
        "Using spaCY NER (https://spacy.io/) for PII checks",
        style="bold blue",
    )

    for filename in args.filenames:
        _, file_extension = os.path.splitext(filename)
        if file_extension in IGNORE_EXTENSIONS:
            console.print(
                f"{filename} ignoring file '{filename}' as extension is ignored by default",
                style="bold red"
            )
        else:
            if filename not in excluded_filenames:
                try:
                    with open(filename, "r") as f:
                        try:
                            console.print(
                                f"{filename} checking for PII",
                                style="bold blue"
                            )
                            for i, line in enumerate(f):
                                if "#PS-IGNORE" in line:
                                    continue

                                if detected_named_entities(line):
                                    exit_code = 1

                        except Exception as ex:
                            # These errors can potentially be ignored
                            console.print(
                                f"{filename} error when attempting to parse file content, ex: '{ex}'.",
                                style="bold red"
                            )
                except EnvironmentError as ex:
                    # Error out of process if we cannot access file
                    console.print(
                        f"{filename} error when attempting to open file, ex: {ex}.",
                        style="bold red"
                    )
                    exit_code = 1

    return exit_code


if __name__ == "__main__":
    exit(main())
