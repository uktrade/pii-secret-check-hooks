import pytest
import os
import json

from pii_secret_check_hooks import hooks_version_check

from pii_secret_check_hooks.config import repo_url


my_path = os.path.abspath(os.path.dirname(__file__))

minimal = os.path.join(my_path, "resources/minimal.yaml")
malformed = os.path.join(my_path, "resources/malformed.yaml")
multiple = os.path.join(my_path, "resources/multiple.yaml")
outororder = os.path.join(my_path, "resources/outoforder.yaml")


@pytest.mark.skip(reason="don't ask")
@pytest.fixture
def mocked_responses():
    with responses.RequestsMock() as rsps:
        yield rsps


@pytest.mark.parametrize(
    "test_input, expected", [(minimal, "v1.0"), (multiple, "v1.0")]
)
def test_local_config(test_input, expected):
    assert hooks_version_check.check_release_version_from_config(test_input) == expected


"""
def test_url(requests_mock):
    requests_mock.get("https://api.github.com/repos/hmrc/security-git-hooks/releases/latest", tag_name = "v1.0")
    response = requests.get("https://api.github.com/repos/hmrc/security-git-hooks/releases/latest")
    assert response.tag_name == "v1.0"

"""


@pytest.mark.skip(reason="don't ask")
def test_response(mocked_responses):
    mocked_responses.add(
        mocked_responses.POST,
        url=repo_url,
        body=json.dumps({"": {"tag_name": "v1.0.0-beta5"}}),
    )

    response = hooks_version_check.check_release_version_from_remote_repo()
    assert "v" in response
