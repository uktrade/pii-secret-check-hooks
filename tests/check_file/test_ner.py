import io
import os

from pii_secret_check_hooks.check_file.ner import CheckForNER


def create_check():
    check_for_ner = CheckForNER(
        excluded_file_list=None,
        excluded_ner_entity_list=None,
    )
    check_for_ner.current_file = "tests/assets/test.txt"
    return check_for_ner


def test_generate_ner_file():
    test_output_file_path = "test_ner_output_file.txt"
    check_for_ner = CheckForNER(
        excluded_file_list=None,
        excluded_ner_entity_list=None,
        ner_output_file=test_output_file_path,
    )
    check_for_ner.entity_list = [
        "test",
    ]

    check_for_ner._generate_ner_file()

    with open(test_output_file_path, 'r', encoding='utf-8') as test_file:
        assert test_file.readline() == "test\n"

    os.remove(test_output_file_path)


def test_generate_ner_file_appends_content(tmp_path):
    dest = tmp_path / "test_generate_ner_file_appends_content.txt"
    dest.write_text("Old foo\n")

    checker = CheckForNER(ner_output_file=dest)
    checker.entity_list = ["New foo"]
    checker._generate_ner_file()

    # The new content is added on the end of the existing content.
    assert dest.read_text() == "Old foo\nNew foo\n"


def test_ner_python_scanner_named_entity_as_variable():
    # The PII is a Python variable, not an issue. Obviously a `Buxton` variable
    # is bad and weird, but in practice we get false positives for _anything_
    # that is capitalized and is not a dictionary word.
    fh = io.StringIO("""Buxton = "The quick brown fox."\n""")

    checker = CheckForNER(allow_changed_lines=True)
    result = checker._issue_found_in_python_content(fh)

    assert result == False


def test_ner_python_scanner_named_entity_in_string():
    # The PII is inside a Python string, it's a problem!
    fh = io.StringIO("""foo = "Buxton."\n""")

    checker = CheckForNER(allow_changed_lines=True)
    result = checker._issue_found_in_python_content(fh)

    assert result == True


def test_ner_python_scanner_named_entity_in_comment():
    # The PII is inside a Python comment, it's a problem!
    fh = io.StringIO("""# Buxton\n""")

    checker = CheckForNER(allow_changed_lines=True)
    result = checker._issue_found_in_python_content(fh)

    assert result == True
