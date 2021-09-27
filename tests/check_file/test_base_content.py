import hashlib
import json
import os
import time
from unittest.mock import MagicMock, patch

from pii_secret_check_hooks.check_file.base_content_check import (
    CheckFileBase,
)
from pii_secret_check_hooks.config import IGNORE_EXTENSIONS


class CheckFileBaseTest(CheckFileBase):
    def line_has_issue(self, line):
        pass

    def after_run(self):
        pass


def load_json(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)


def create_base():
    check_base = CheckFileBaseTest(
        check_name="test_base",
    )
    check_base.log_data = load_json("tests/assets/log_file_unchanged.json")
    return check_base


def create_test_base_for_line_test():
    check_base = CheckFileBaseTest(
        check_name="test_base",
    )
    check_base.interactive = True
    check_base.log_data["excluded_lines"] = {
        "foo/bar/test.py": {
            "line": 1,
        }
    }
    check_base.current_file = "foo/bar/test.py"

    return check_base


@patch('pii_secret_check_hooks.check_file.base_content_check.load_json')
def test_log_updated(load_json):
    load_json.return_value = {
        "files": {
            "tests/assets/test.txt": {
                "hash": "291f89e4b12779a5cbef6f508f5e593dea9dd9b4"
            }
        },
        "excluded_lines": {
            "tests/assets/test.txt": {
                "line": 11,
                "hash": "c5d191810c3a09a99f73ca145a4ce34e09a94790"
            }
        }
    }
    check_base = CheckFileBaseTest(
        check_name="test_base",
    )
    assert "tests/assets/test.txt" in check_base.log_data["files"]

    output_file_path = f"tests/check_output_{str(time.time())}.txt"
    check_base.log_path = output_file_path
    check_base._write_log()

    with open(output_file_path, 'r') as json_file:
        assert "tests/assets/test.txt" in load_json(json_file)["files"]

    os.remove(output_file_path)


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
    )


def test_file_excluded():
    check_base = create_base()
    check_base.excluded_file_list = ["excluded.txt"]
    assert check_base._file_excluded("excluded.txt")


def test_file_changed():
    check_base = CheckFileBaseTest(
        check_name="test_base",
        excluded_file_list=[],
    )
    check_base.log_data = load_json("tests/assets/log_file_changed.json")
    check_base.current_file = "tests/assets/test.txt"

    check_base_1 = CheckFileBaseTest(
        check_name="test_base",
        excluded_file_list=[],
    )
    check_base_1.log_data = load_json("tests/assets/log_file_unchanged.json")
    check_base_1.current_file = "tests/assets/test.txt"

    with open("tests/assets/test.txt", 'r', encoding='utf-8') as test_file:
        assert check_base._file_changed(
            test_file,
        )

        assert not check_base_1._file_changed(
            test_file,
        )


def test_file_changed_file_added():
    check_base = CheckFileBaseTest(
        check_name="test_base",
        excluded_file_list=[],
    )
    check_base.log_data = load_json("tests/assets/log_file_changed.json")
    check_base.current_file = "tests/assets/test-1.txt"

    with open("tests/assets/test-1.txt", 'r', encoding='utf-8') as test_file:
        assert check_base._file_changed(
            test_file,
        )


def test_line_has_changed():
    check_base = CheckFileBaseTest(
        check_name="test_base",
        excluded_file_list=[],
    )
    check_base.current_file = "tests/assets/test.txt"
    check_base.log_data = load_json("tests/assets/log_file_unchanged.json")

    assert not check_base._line_has_changed(
        line_num=11,
        line="A piece of test text",
    )

    assert check_base._line_has_changed(
        line_num=11,
        line="A different piece of test text",
    )


def test_update_line_hash():
    check_base = create_base()
    check_base.current_file = "tests/assets/test.txt"

    check_base._update_line_hash(14, "I am a test")

    assert check_base.log_data["excluded_lines"]["tests/assets/test.txt"]["line"] == 14
    assert check_base.log_data["excluded_lines"]["tests/assets/test.txt"]["hash"] == "c3207bbe306d89116d4058320b086296a43b8964"


@patch('pii_secret_check_hooks.check_file.base_content_check.input', return_value='y')
def test_process_file_content_input_y(mock_input):
    check_base = create_test_base_for_line_test()

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    check_base._issue_found_in_file_content(mock)

    assert check_base.log_data["excluded_lines"]["foo/bar/test.py"]["line"] == 1
    assert check_base.log_data["excluded_lines"]["foo/bar/test.py"]["hash"] == "16596042a0a654eab33e1a02e2aae731e9b8a4c4"


@patch('pii_secret_check_hooks.check_file.base_content_check.input', return_value='x')
def test_process_file_content_input_not_y(mock_input):
    check_base = create_test_base_for_line_test()

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    found_issue = check_base._issue_found_in_file_content(mock)
    assert found_issue


def test_process_file_content_non_interactive():
    check_base = create_test_base_for_line_test()
    check_base.interactive = False

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    found_issue = check_base._issue_found_in_file_content(mock)
    assert not found_issue


def test_issue_found_in_file_creates_log_for_no_issue_files():
    test_file_name = "tests/assets/test-1.txt"
    check_base = create_base()
    check_base.current_file = test_file_name
    check_base._file_changed = MagicMock(return_value=True)
    check_base._issue_found_in_file_content = MagicMock(
        return_value=False,
    )
    check_base._create_file_hash = MagicMock(
        return_value="fake_hash",
    )
    check_base._issue_found_in_file(test_file_name)

    assert check_base.log_data["files"][test_file_name]["hash"] == "fake_hash"
