from pathlib import Path


def get_excluded_filenames(file_path):
    exclude_file = Path(file_path)
    if not exclude_file.is_file():
        print(f"Could not find path {file_path}")
        return []

    exclude_file_names = []

    with open(file_path, "r") as exclude_file:
        for line in exclude_file:
            stripped_line = line.strip()
            exclude_file_names.append(stripped_line)

    return exclude_file_names


def get_regex(file_path):
    regex_file = Path(file_path)
    if not regex_file.is_file():
        print(f"Could not find path {file_path}")
        return []

    regex = []
    with open(file_path, "r") as regex_file:
        for line in regex_file:
            stripped_line = line.strip()
            # Check for comment
            if not stripped_line.strip().startswith("#"):
                regex.append(stripped_line)

    return regex
