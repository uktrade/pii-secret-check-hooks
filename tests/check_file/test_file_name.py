from pii_secret_check_hooks.check_file.file_name import (
    check_file_names,
    _detect_match_against_filename,
)


def test_detect_match_against_filename():
    assert _detect_match_against_filename("test.txt",  [r"\.txt$", ],)
    assert not _detect_match_against_filename("test.pdf",  [r"\.txt$", ],)


def test_check_file_names():
    assert check_file_names(
        ["test.txt", ],
    )

    assert not check_file_names(
        ["test.not_of_concern", ],
    )
