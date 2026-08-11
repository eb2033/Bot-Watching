from pathlib import Path

import geoip2.database
from geoip2.errors import AddressNotFoundError

_DATA_DIR = Path(__file__).resolve().parent / "data"
_CITY_DB = _DATA_DIR / "GeoLite2-City.mmdb"
_ASN_DB = _DATA_DIR / "GeoLite2-ASN.mmdb"


def _require_databases() -> None:
    """Fail with an actionable message when the GeoLite2 files are absent.
    The GeoLite2 databases are not included in this repository because they are
    licensed by MaxMind under a restrictive license.
    """
    missing = [db.name for db in (_CITY_DB, _ASN_DB) if not db.is_file()]
    if not missing:
        return

    raise RuntimeError(
        f"Missing GeoLite2 database(s): {', '.join(missing)}. "
        f"Expected in {_DATA_DIR}. Download the free GeoLite2 City and ASN "
        "databases from MaxMind (https://www.maxmind.com/en/geolite2/signup) "
        f"and place them there using those exact filenames - see {_DATA_DIR / 'readme.md'}."
    )


_require_databases()

_city_reader = geoip2.database.Reader(str(_CITY_DB))
_asn_reader = geoip2.database.Reader(str(_ASN_DB))

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
        "latitude": city_resp.location.latitude,
        "longitude": city_resp.location.longitude,
    }