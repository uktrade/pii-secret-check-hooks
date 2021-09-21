import hashlib
import json
from unittest.mock import MagicMock, patch
import pytest

from pii_secret_check_hooks.check_file.base_content_check import (
    CheckFileBase,
    LineHashChangedException,
)
from pii_secret_check_hooks.config import IGNORE_EXTENSIONS


class CheckFileBaseTest(CheckFileBase):
    def process_line(self, line):
        pass


def load_json(file_path):
    with open(file_path, 'r') as json_file:
        return json.load(json_file)


def create_base():
    check_base = CheckFileBaseTest(
        excluded_file_list=None,
    )
    check_base.log_data = load_json("tests/assets/log_file_unchanged.json")
    return check_base


def create_test_base_for_line_test():
    check_base = CheckFileBaseTest(
        excluded_file_list=None,
    )
    check_base.interactive = True
    check_base.log_data["excluded_lines"] = {
        "foo/bar/test.py": {
            "line": 1,
        }
    }
    check_base.current_file = "foo/bar/test.py"

    return check_base


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
    check_base = CheckFileBaseTest(
        excluded_file_list=None,
    )
    check_base.log_data = load_json("tests/assets/log_file_changed.json")
    check_base.current_file = "tests/assets/test.txt"

    check_base_1 = CheckFileBaseTest(
        excluded_file_list=None,
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


def test_line_has_changed():
    check_base = CheckFileBaseTest(
        excluded_file_list=None,
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

    check_base._process_file_content(mock)

    assert check_base.log_data["excluded_lines"]["foo/bar/test.py"]["line"] == 1
    assert check_base.log_data["excluded_lines"]["foo/bar/test.py"]["hash"] == "16596042a0a654eab33e1a02e2aae731e9b8a4c4"


@patch('pii_secret_check_hooks.check_file.base_content_check.input', return_value='x')
def test_process_file_content_input_not_y(mock_input):
    check_base = create_test_base_for_line_test()

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    with pytest.raises(LineHashChangedException):
        check_base._process_file_content(mock)
