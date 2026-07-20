from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

_DATA_DIR = Path(__file__).resolve().parent / "data"
_city_reader = geoip2.database.Reader(str(_DATA_DIR / "GeoLite2-City.mmdb"))
_asn_reader = geoip2.database.Reader(str(_DATA_DIR / "GeoLite2-ASN.mmdb"))

def lookup_ip(src_ip: str) -> dict | None:
    try:
        city_resp = _city_reader.city(src_ip)
        asn_resp = _asn_reader.asn(src_ip)
    except AddressNotFoundError:
        return None

    return {
        "country": city_resp.country.name,
        "city": city_resp.city.name,
        "asn": str(asn_resp.autonomous_system_number),
        "org": asn_resp.autonomous_system_organization,
    }