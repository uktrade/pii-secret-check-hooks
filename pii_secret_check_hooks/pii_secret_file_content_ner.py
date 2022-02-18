import argparse
from rich.console import Console

from pii_secret_check_hooks.util import (
    get_excluded_filenames,
    get_excluded_ner,
)
from pii_secret_check_hooks.check_file.ner import CheckForNER
from pii_secret_check_hooks.util import print_error, print_info


console = Console()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "filenames",
        nargs="*",
        help="Files to check",
    )
    parser.add_argument(
        "--exclude",
        nargs="?",
        default="pii-secret-exclude.txt",
        help="Exclude file path",
    )
    parser.add_argument(
        "--ner_exclude",
        nargs="?",
        default="pii-ner-exclude.txt",
        help="Named Entity Recognition exclude file path. One per line.",
    )
    parser.add_argument(
        "--ner_output_file",
        nargs="?",
        default=None,
        help="File for outputting exclude data to",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)
    excluded_entities = get_excluded_ner(args.ner_exclude)
    ner_output_file = args.ner_output_file

    print_info(
        "Using spaCY NER (https://spacy.io/) for PII checks",
    )

    if ner_output_file:
        print_info(f"NER excludes will be appended to '{ner_output_file}'")

    process_ner_file = CheckForNER(
        allow_changed_lines=True,
        excluded_file_list=excluded_filenames,
        excluded_ner_entity_list=excluded_entities,
        ner_output_file=ner_output_file,
    )

    if process_ner_file.process_files(args.filenames):
        print_error(
            "NER content check failed",
        )
        return 1

    print_info("NER checks passed")
    return 0


if __name__ == "__main__":
    exit(main())
