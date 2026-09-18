"""Test fixtures: run the demo apps in-process on ephemeral ports."""
import http.server
import importlib
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


def _serve(module_name):
    mod = importlib.import_module(module_name)
    if hasattr(mod, "seed"):
        mod.seed()
    httpd = http.server.HTTPServer(("127.0.0.1", 0), mod.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, f"http://127.0.0.1:{httpd.server_address[1]}/"


@pytest.fixture(scope="session")
def vuln_url():
    httpd, url = _serve("vulnerable_app")
    yield url
    httpd.shutdown()


@pytest.fixture(scope="session")
def secure_url():
    httpd, url = _serve("secure_app")
    yield url
    httpd.shutdown()
