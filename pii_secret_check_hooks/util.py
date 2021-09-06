
def get_excluded_filenames(file_path):
    exclude_file_names = []

    with open(file_path, "r") as a_file:
        for line in a_file:
            stripped_line = line.strip()
            exclude_file_names.append(stripped_line)

    return exclude_file_names


def get_regex(file_name):
    regex = []
    with open(file_name, "r") as a_file:
        for line in a_file:
            stripped_line = line.strip()
            # Check for comment
            if not stripped_line.strip().startswith("#"):
                regex.append(stripped_line)

    return regex
