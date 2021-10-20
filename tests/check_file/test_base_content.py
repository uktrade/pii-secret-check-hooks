import functools
import io
import hashlib
import json
import os
import pathlib

import pytest
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


def remove_log(test_log_dir):
    try:
        os.remove(pathlib.Path(test_log_dir) / "pii-secret-log")
    except FileNotFoundError:
        pass
    os.rmdir(test_log_dir)


@pytest.fixture
def json_log_data():
    return {
        "files": {
            "tests/assets/test.txt": {
                "hash": "291f89e4b12779a5cbef6f508f5e593dea9dd9b4"
            }
        }
    }


@pytest.fixture
def json_log_data_content(json_log_data):
    return io.StringIO(json.dumps(json_log_data))


@pytest.fixture(scope="module")
def log_dir(request):
    test_log_dir = ".pii-secret-hook/test_base"
    request.addfinalizer(functools.partial(remove_log, test_log_dir))
    return test_log_dir


def test_log_pre_populated(json_log_data_content, log_dir):
    with patch(
            "pii_secret_check_hooks.check_file.base_content_check.open",
            return_value=json_log_data_content,
            create=True
    ):
        check_base = CheckFileBaseTest(check_name="test_base")
        assert os.stat(log_dir)
        assert check_base.log_path == f"{log_dir}/pii-secret-log"
        assert "tests/assets/test.txt" in check_base.log_data["files"]
        assert "hash" in check_base.log_data["files"]["tests/assets/test.txt"]


def test_log_updated(json_log_data, log_dir):
    check_base = CheckFileBaseTest(check_name="test_base")
    check_base.log_data = json_log_data
    check_base._write_log()
    with open(check_base.log_path, 'r') as json_file:
        assert check_base.log_path == f"{log_dir}/pii-secret-log"
        assert "tests/assets/test.txt" in load_json(json_file.name)["files"]


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


def test_file_excluded_file():
    check_base = create_base()
    check_base.excluded_file_list = ["excluded.txt"]
    assert check_base._file_excluded("excluded.txt")


def test_file_excluded_path():
    check_base = create_base()
    check_base.excluded_file_list = ["/i/am/a/"]
    assert check_base._file_excluded("/i/am/a/test/excluded.txt")


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


def test_process_file_content_line_with_marker_file_changed_allow_changed_lines():
    check_base = CheckFileBaseTest(
        check_name="test_base",
    )
    check_base.allow_changed_lines = True

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    assert not check_base._issue_found_in_file_content(mock)


def test_process_file_content_line_with_marker_file_changed_disallow_changed_lines():
    check_base = CheckFileBaseTest(
        check_name="test_base",
    )
    check_base.line_has_issue = MagicMock()
    check_base.line_has_issue.return_value = True
    check_base.allow_changed_lines = False

    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    assert check_base._issue_found_in_file_content(mock)


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
