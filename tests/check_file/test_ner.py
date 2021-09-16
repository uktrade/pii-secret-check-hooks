import hashlib

from pii_secret_check_hooks.check_file.ner import CheckForNER


def get_line_with_hash(line):
    line_sha1 = hashlib.sha1()
    line_sha1.update(line.encode('utf-8'))
    parts = line.split("#PS-IGNORE")

    if len(parts) > 1:
        return f"{parts[0]}#PS-IGNORE {line_sha1.hexdigest()}{parts[1]}"
    else:
        return f"{line} {line_sha1.hexdigest()}"


def test_line_has_changed():
    test_line_with_hash = get_line_with_hash("I am a test #PS-IGNORE")
    test_line_with_hash_1 = get_line_with_hash("I am a test #PS-IGNORE more text")
    test_line = "I am a test #PS-IGNORE"
    test_line_1 = "I am a test #PS-IGNORE more text"
    check_for_ner = CheckForNER(None, None)

    assert not check_for_ner.line_has_changed(test_line_with_hash)
    assert not check_for_ner.line_has_changed(test_line_with_hash_1)
    assert check_for_ner.line_has_changed(test_line)
    assert check_for_ner.line_has_changed(test_line_1)


def test_update_line_hash():
    test_line = "I am a test #PS-IGNORE"
