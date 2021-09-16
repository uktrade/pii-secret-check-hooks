from pii_secret_check_hooks.check_file.ner import CheckForNER, LineHashChangedException
from unittest.mock import MagicMock, patch
import pytest


def create_check():
    return CheckForNER(
        filename="foo/bar/test.py",
        excluded_file_list=None,
        excluded_entity_list=None,
        log_path="tests/example_file_log.json",
    )


def test_get_line_has_changed():
    check_for_ner = create_check()
    has_changed = check_for_ner.line_has_changed(
        line_num=11,
        line="A piece of test text",
    )

    assert not has_changed

    has_changed = check_for_ner.line_has_changed(
        line_num=11,
        line="A different piece of test text",
    )

    assert has_changed


def test_update_line_hash():
    check_for_ner = create_check()

    check_for_ner.update_line_hash(14, "I am a test")

    assert check_for_ner.log_data["excluded_lines"]["foo/bar/test.py"]["line"] == 14
    assert check_for_ner.log_data["excluded_lines"]["foo/bar/test.py"]["hash"] == "c3207bbe306d89116d4058320b086296a43b8964"


@patch('pii_secret_check_hooks.check_file.ner.input', return_value='y')
def test_process_from_line(mock_input):
    check_for_ner = create_check()
    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    check_for_ner.process_file_content(mock)

    assert check_for_ner.log_data["excluded_lines"]["foo/bar/test.py"]["line"] == 1
    assert check_for_ner.log_data["excluded_lines"]["foo/bar/test.py"]["hash"] == "16596042a0a654eab33e1a02e2aae731e9b8a4c4"


@patch('pii_secret_check_hooks.check_file.ner.input', return_value='x')
def test_process_from_line(mock_input):
    check_for_ner = create_check()
    mock = MagicMock()
    mock.__iter__.return_value = ["I am a test. #PS-IGNORE", "So am I.", ]

    with pytest.raises(LineHashChangedException):
        check_for_ner.process_file_content(mock)
