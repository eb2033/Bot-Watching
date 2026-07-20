from __future__ import annotations

import sys
from pathlib import Path

import pytest


TEST_DIR = Path(__file__).resolve().parent
ENGINE_ROOT = TEST_DIR.parent
PROJECT_ROOT = ENGINE_ROOT.parent
PROJECT_ROOT_STR = str(PROJECT_ROOT)
ENGINE_ROOT_STR = str(ENGINE_ROOT)

if PROJECT_ROOT_STR not in sys.path:
	sys.path.insert(0, PROJECT_ROOT_STR)

if ENGINE_ROOT_STR not in sys.path:
	sys.path.insert(0, ENGINE_ROOT_STR)

TEST_FILES = [
    (TEST_DIR / "test_models.py", "Model tests"),
    (TEST_DIR / "test_rules.py", "Rule tests"),
    (TEST_DIR / "test_db_session.py", "Database session tests"),
    (TEST_DIR / "test_crud.py", "CRUD tests"),
    (TEST_DIR / "test_listener.py", "Listener tests"),
]


def main() -> int:
    results: list[tuple[str, int]] = []

    for test_file, test_name in TEST_FILES:
        print(f"\n=== Running {test_name} ===")
        result = pytest.main([str(test_file), "-v"])
        results.append((test_name, int(result)))
        if result != 0:
            print(f"=== {test_name} failed ===")
            break
        print(f"=== {test_name} passed ===")

    print("\n=== Test Summary ===")
    for test_name, result in results:
        status = "PASSED" if result == 0 else "FAILED"
        print(f"{test_name}: {status}")

    return 0 if all(result == 0 for _, result in results) else next(result for _, result in results if result != 0)


if __name__ == "__main__":
	raise SystemExit(main())