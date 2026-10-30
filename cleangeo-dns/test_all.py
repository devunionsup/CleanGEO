"""Run every suite and print one total.

    python test_all.py           # all four suites
    python test_all.py -q        # quieter

Each suite is loaded by file path, not by name: a bare `import test_doh` makes
the runner try to install a package called test_doh before the code runs.
"""
from __future__ import annotations

import importlib.util
import pathlib
import sys
import unittest

# Declared here on purpose: the runner resolves third-party packages from the
# entry file's own imports, so a suite loaded dynamically would otherwise start
# before h2 or cryptography were installed. Importing them here makes the
# dependency real for this entry point.
import cryptography  # noqa: F401
import h2  # noqa: F401

HERE = pathlib.Path(__file__).resolve().parent
SUITES = ("test_resolver", "test_doh", "test_cstp", "test_integration")


def load_suite(name: str):
    path = HERE / (name + ".py")
    spec = importlib.util.spec_from_file_location("suite_" + name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main(argv) -> int:
    verbosity = 1 if "-q" in argv else 2
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    for name in SUITES:
        suite.addTests(loader.loadTestsFromModule(load_suite(name)))
    result = unittest.TextTestRunner(verbosity=verbosity).run(suite)

    total = result.testsRun
    failed = len(result.failures) + len(result.errors)
    print("\n%d tests, %d failed, %d skipped"
          % (total, failed, len(result.skipped)))
    if failed:
        return 1
    print("OK: all %d tests passed" % total)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
