from __future__ import annotations

import pytest

from enrichment import enrichment
from enrichment.enrichment import lookup_ip


def test_missing_geolite_databases_raise_actionable_error(tmp_path, monkeypatch):
    # A fresh clone has no .mmdb files (they're gitignored), so this must fail
    # with something that says what's missing and where to get it - not the
    # bare FileNotFoundError maxminddb raises from inside the import.
    monkeypatch.setattr(enrichment, "_CITY_DB", tmp_path / "GeoLite2-City.mmdb")
    monkeypatch.setattr(enrichment, "_ASN_DB", tmp_path / "GeoLite2-ASN.mmdb")

    with pytest.raises(RuntimeError) as excinfo:
        enrichment._require_databases()

    message = str(excinfo.value)
    assert "GeoLite2-City.mmdb" in message
    assert "GeoLite2-ASN.mmdb" in message
    assert "maxmind.com" in message


def test_require_databases_passes_when_both_present():
    # The real files are present in this checkout, so this must not raise.
    enrichment._require_databases()


def test_lookup_ip_returns_geo_and_coordinates_for_known_public_ip():
	result = lookup_ip("8.8.8.8")

	assert result is not None
	assert result["country"] == "United States"
	assert isinstance(result["latitude"], float)
	assert isinstance(result["longitude"], float)


def test_lookup_ip_returns_none_for_private_address():
	assert lookup_ip("10.0.0.1") is None
