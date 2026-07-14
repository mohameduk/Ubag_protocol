"""Cross-language parity — Python extraction must match the shared golden.

The Node suite (ubag-node/tests/parity.test.js) asserts against the same golden
file, so if both pass, both SDKs produce identical JSON-LD for the same HTML.
"""
import json
from pathlib import Path

import pytest

from ubag._extract import extract_structured_data

FIXTURES = Path(__file__).resolve().parents[2] / "tests" / "fixtures"
GOLDEN = json.loads((FIXTURES / "expected_jsonld.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("name", sorted(GOLDEN.keys()))
def test_jsonld_matches_golden(name):
    html = (FIXTURES / name).read_text(encoding="utf-8")
    extracted = extract_structured_data(html)["jsonld"]
    assert extracted == GOLDEN[name]
