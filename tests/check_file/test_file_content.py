from pii_secret_check_hooks.check_file.file_content import (
    CheckFileContent,
)


def test_entropy_check():
    check_file_content = CheckFileContent(
        excluded_file_list=None,
        custom_regex_list=None,
    )

    assert check_file_content._entropy_check(
        # High entropy random chars
        "6F28CA8A9CBD6FA88FC29A35D8257D0B1717C2D9384D4B25F5F29B82C07A2EB2",
    )

    assert not check_file_content._entropy_check(
        "No entropy here",
    )


def test_trufflehog_check():
    check_file_content = CheckFileContent(
        excluded_file_list=None,
        custom_regex_list=None,
    )

    # Use AWS key string as regex is present in TruffleHog regex project
    assert check_file_content._trufflehog_check(
        "test AKIA11111111AAAAAAAA test"
    )


def test_pii_regex():
    check_file_content = CheckFileContent(
        excluded_file_list=None,
        custom_regex_list=None,
    )

    assert check_file_content._pii_regex(
        "I am a line, with Buckingham Palace's postcode - SW1A 1AA"
    )

    assert not check_file_content._pii_regex(
        "I do not contain any PII"
    )


def test_custom_regex_checks():
    check_file_content = CheckFileContent(
        excluded_file_list=None,
        custom_regex_list=[
            r"dog name=(\s*)dog(\s*)name(\s*)"
        ],
    )

    assert check_file_content._custom_regex_checks(
        "My dog name is Rover"
    )

    assert not check_file_content._custom_regex_checks(
        "I do not contain any names of dogd"
    )
