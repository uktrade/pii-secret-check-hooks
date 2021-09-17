import hashlib
from io import StringIO

from pii_secret_check_hooks.check_file.base import CheckFileBase

from pii_secret_check_hooks.config import IGNORE_EXTENSIONS


def create_base():
    return CheckFileBase(
        excluded_file_list=None,
        log_path="tests/assets/log_file_unchanged.json",
    )


def test_create_file_hash():
    sha1 = hashlib.sha1()
    content = "I am file content"
    sha1.update(content.encode("utf-8"))
    content_hash = sha1.hexdigest()

    check_base = create_base()
    with open("tests/assets/test.txt", 'r', encoding='utf-8') as test_file:
        file_content_hash = check_base._create_file_hash(test_file)
        assert content_hash == file_content_hash


def test_file_extension_excluded():
    check_base = create_base()
    test_filename = f"test{IGNORE_EXTENSIONS[0]}"
    assert check_base._file_extension_excluded(
        test_filename,
        IGNORE_EXTENSIONS,
    )


def test_file_excluded():
    check_base = create_base()
    assert check_base._file_excluded("excluded.txt", ["excluded.txt"])


def test_file_changed():
    check_base = CheckFileBase(
        excluded_file_list=None,
        log_path="tests/assets/log_file_changed.json",
    )
    check_base.current_file = "tests/assets/test.txt"

    check_base_1 = CheckFileBase(
        excluded_file_list=None,
        log_path="tests/assets/log_file_unchanged.json",
    )
    check_base_1.current_file = "tests/assets/test.txt"

    with open("tests/assets/test.txt", 'r', encoding='utf-8') as test_file:
        assert check_base._file_changed(
            test_file,
        )

        assert not check_base_1._file_changed(
            test_file,
        )
