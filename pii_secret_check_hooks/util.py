import logging
from pathlib import Path
from rich.console import Console


console = Console()


def _get_file_content_as_list(file_path, file_type, lower=False):
    file = Path(file_path)
    if not file.is_file():
        logging.info(f"No {file_type} file found in path {file_path}")
        return []

    logging.info(f"Found {file_type} file '{file_path}'")

    lines = []

    with open(file_path, "r") as exclude_file:
        for line in exclude_file:
            stripped_line = line.strip()
            if lower:
                stripped_line = stripped_line.lower()
            lines.append(stripped_line)

    logging.info(f"Found {len(lines)} files in {file_type} file")

    return lines


def get_regex_from_file(file_path):
    return _get_file_content_as_list(file_path, "custom regex")


def get_excluded_filenames(file_path):
    return _get_file_content_as_list(file_path, "exclude")


def get_excluded_ner(file_path):
    return _get_file_content_as_list(file_path, "exclude NER", lower=True)


def print_error(message):
    console.print(
        message,
        style="bold red",
        soft_wrap=True,
    )


def print_info(message):
    console.print(
        message,
        style="white on blue",
        soft_wrap=True,
    )


def print_warning(message):
    console.print(
        message,
        style="white on green",
        soft_wrap=True,
    )
