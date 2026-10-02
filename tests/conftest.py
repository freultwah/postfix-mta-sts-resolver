import os

import pytest

from postfix_mta_sts_resolver.utils import enable_uvloop


@pytest.fixture(scope="session", autouse=True)
def _uvloop_check():
    uvloop_test = os.environ.get('TOXENV', '').endswith('-uvloop')
    uvloop_enabled = enable_uvloop()
    assert uvloop_test == uvloop_enabled
