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
