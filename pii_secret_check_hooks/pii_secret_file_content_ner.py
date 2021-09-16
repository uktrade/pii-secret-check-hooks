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
from pii_secret_check_hooks.check_file.base import (
    LineUpdatedException,
    FoundSensitiveException,
)

from pii_secret_check_hooks.check_file.ner import CheckForNER

nlp = en_core_web_sm.load()

console = Console()


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
        default=".pii-ner-exclude",
        help="Named Entity Recognition exclude file path. One per line.",
    )
    parser.add_argument(
        "exclude_output",
        nargs="?",
        default=None,
        help="File for outputting exclude data to",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)
    excluded_entities = get_excluded_ner(args.ner_exclude)
    exclude_file = args.exclude_output

    # Exclude custom regex file
    excluded_filenames.append(args.exclude)

    exit_code = 0

    console.print(
        "Using spaCY NER (https://spacy.io/) for PII checks",
        style="white on blue",
        soft_wrap=True,
    )

    process_ner_file = CheckForNER(
        excluded_filenames,
        excluded_entities,
    )

    for filename in args.filenames:
        _, file_extension = os.path.splitext(filename)
        if file_extension not in IGNORE_EXTENSIONS:
            try:
                process_ner_file.process_file(filename)
            except LineUpdatedException:
                exit_code = 1

    return exit_code


if __name__ == "__main__":
    exit(main())
