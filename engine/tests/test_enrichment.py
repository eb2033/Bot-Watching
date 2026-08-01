from __future__ import annotations

from enrichment.enrichment import lookup_ip


def test_lookup_ip_returns_geo_and_coordinates_for_known_public_ip():
	result = lookup_ip("8.8.8.8")

	assert result is not None
	assert result["country"] == "United States"
	assert isinstance(result["latitude"], float)
	assert isinstance(result["longitude"], float)


def test_lookup_ip_returns_none_for_private_address():
	assert lookup_ip("10.0.0.1") is None
