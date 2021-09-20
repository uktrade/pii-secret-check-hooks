from pii_secret_check_hooks.check_file.file_content import (
    CheckFileContent,
)


def test_entropy_check():
    check_file_content = CheckFileContent(
        excluded_file_list=None,
        custom_regex_list=None,
    )

    assert check_file_content._entropy_check(
        "dGhpcyBpcyBhbm90aGVyIHRlc3Q=",
    )

    assert not check_file_content._entropy_check(
        "No entropy here",
    )


def test_process_line():
    pass
