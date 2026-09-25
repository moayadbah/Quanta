"""File roles (Master Plan 7.2). Only ``source`` counts toward the score."""

from __future__ import annotations

import pytest

from quanta.core.roles import classify_role


@pytest.mark.parametrize(
    ("path", "role"),
    [
        ("src/pkg/a.py", "source"),
        ("tests/test_a.py", "test"),
        ("pkg/tests/helpers.py", "test"),
        ("pkg/test_a.py", "test"),
        ("pkg/a_test.py", "test"),
        ("conftest.py", "test"),
        ("docs/conf.py", "docs"),
        ("examples/client.py", "example"),
        ("src/pkg/_vendor/six.py", "vendored"),
        ("scripts/release.py", "tooling"),
        ("Tests/Test_A.py", "test"),
        ("pkg/testing_utils.py", "source"),
    ],
)
def test_roles(path: str, role: str) -> None:
    assert classify_role(path) == role
