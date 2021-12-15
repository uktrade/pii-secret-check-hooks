import pytest
from unittest import mock

from pii_secret_check_hooks import (
    pii_secret_filename,
    pii_secret_file_content,
    pii_secret_file_content_ner
)


@pytest.fixture
def expected_args():
    return ["foo.txt"]


@pytest.fixture
def expected_kwargs():
    return [
        ".pii-secret-hook/file_content/pii-secret-log",
        ".pii-secret-hook/ner/pii-secret-log",
        "pii-secret-exclude.txt",
        "pii-ner-exclude.txt",
        "pii-custom-regex.txt",
    ]


@pytest.fixture
def process_files():
    return mock.Mock(return_value=False)


@pytest.fixture
def get_excluded_filenames():
    return mock.Mock()


def test_pii_secret_file_content_defaults(monkeypatch, process_files, get_excluded_filenames):
    get_regex_from_file = mock.Mock()
    monkeypatch.setattr(pii_secret_file_content, "get_excluded_filenames", get_excluded_filenames)
    monkeypatch.setattr(pii_secret_file_content, "get_regex_from_file", get_regex_from_file)
    monkeypatch.setattr(pii_secret_file_content.CheckFileContent, "process_files", process_files)
    pii_secret_file_content.main(argv=["foo.txt"])
    process_files.assert_called_with(["foo.txt"])
    get_excluded_filenames.assert_called_with("pii-secret-exclude.txt")
    get_regex_from_file.assert_called_with("pii-custom-regex.txt")


def test_pii_secret_file_content_ner_defaults(monkeypatch, process_files, get_excluded_filenames):
    get_excluded_ner = mock.Mock()
    monkeypatch.setattr(pii_secret_file_content_ner, "get_excluded_filenames", get_excluded_filenames)
    monkeypatch.setattr(pii_secret_file_content_ner, "get_excluded_ner", get_excluded_ner)
    monkeypatch.setattr(pii_secret_file_content_ner.CheckForNER, "process_files", process_files)
    pii_secret_file_content_ner.main(argv=["foo.txt"])
    process_files.assert_called_with(["foo.txt"])
    get_excluded_filenames.assert_called_with("pii-secret-exclude.txt")
    get_excluded_ner.assert_called_with("pii-ner-exclude.txt")


def test_pii_secret_filename_defaults(monkeypatch, expected_args, expected_kwargs):
    check_file_names = mock.Mock()
    monkeypatch.setattr(pii_secret_filename, "check_file_names", check_file_names)
    pii_secret_filename.main(argv=["foo.txt"])
    check_file_names.assert_called_with(expected_args, expected_kwargs)
