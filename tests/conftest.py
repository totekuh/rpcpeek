import hashlib
from pathlib import Path

import pytest

from rpcpeek.cli import analyze_file


FIXTURE_DIR = Path(__file__).parent / "fixtures"
MPSVC_DLL = FIXTURE_DIR / "MpSvc_4.18.26060.3008.dll"
LSASRV_DLL = FIXTURE_DIR / "lsasrv.dll"
NORPC_DLL = FIXTURE_DIR / "empty_norpc.dll"

FIXTURE_HASHES = {
    "MpSvc_4.18.26060.3008.dll": "ea5e4b2d4971f0138e77985424d89cb42bc2199fad02020883ba5925f9de251e",
    "lsasrv.dll": "1b54993670658baabea2e7e8b3192fe92fd5b68ef5456d66dec3a4d1527cf11c",
    "empty_norpc.dll": "1d9fb95143f51f2b29e0cde7a8f67fd7a5177e4397908f8d6e18c48cd660753f",
}


@pytest.fixture(scope="session", autouse=True)
def verify_fixture_integrity():
    for name, expected in FIXTURE_HASHES.items():
        path = FIXTURE_DIR / name
        assert path.exists(), f"Fixture DLL not found: {path}"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected, f"Fixture {name} hash mismatch: {actual}"


@pytest.fixture
def fixture_dll():
    return MPSVC_DLL


@pytest.fixture
def lsasrv_dll():
    return LSASRV_DLL


@pytest.fixture(scope="session")
def parsed_result():
    return analyze_file(MPSVC_DLL)


@pytest.fixture(scope="session")
def lsasrv_result():
    return analyze_file(LSASRV_DLL)


@pytest.fixture(scope="session")
def dll_bytes():
    return MPSVC_DLL.read_bytes()


@pytest.fixture(scope="session")
def lsasrv_bytes():
    return LSASRV_DLL.read_bytes()


@pytest.fixture
def norpc_dll():
    return NORPC_DLL


@pytest.fixture(scope="session")
def norpc_result():
    return analyze_file(NORPC_DLL)


@pytest.fixture(scope="session")
def norpc_bytes():
    return NORPC_DLL.read_bytes()
