import argparse

from pii_secret_check_hooks.util import (
    get_regex_from_file,
    get_excluded_filenames,
)
from pii_secret_check_hooks.check_file.file_content import (
    CheckFileContent,
)
from pii_secret_check_hooks.util import print_error, print_info


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
        "--regex_file",
        nargs="?",
        default="pii-custom-regex.txt",
        help="File with custom regex (one per line)",
    )
    args = parser.parse_args(argv)
    excluded_filenames = get_excluded_filenames(args.exclude)
    custom_regex_list = get_regex_from_file(args.regex_file)

    # Exclude custom regex file
    excluded_filenames.append(args.regex_file)

    process_file_content = CheckFileContent(
        allow_changed_lines=True,
        excluded_file_list=excluded_filenames,
        custom_regex_list=custom_regex_list,
    )

    if process_file_content.process_files(args.filenames):
        print_error(
            "File content check failed",
        )
        return 1

    print_info("File content checks passed")
    return 0


if __name__ == "__main__":
    exit(main())
