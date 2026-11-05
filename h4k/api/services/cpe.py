"""CPE auto-correlate (Backlog #22).

Banner text ("Apache/2.4.49", "OpenSSH_7.4") is not an identity. This
module canonicalizes a fingerprinted service into a CPE 2.3 string
(`cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*`) and reuses the
banner-aware `CveDb.match_service` for the actual CVE correlation —
so a patched vsftpd 3.0.3 is never flagged with the 2.3.4 backdoor CVE.
Vendor inference covers the famous products; unknown vendors fall back
to the product name rather than inventing one.
"""

from __future__ import annotations

import re
from typing import Any

VENDOR_MAP = {
    "apache": "apache",
    "apache httpd": "apache",
    "httpd": "apache",
    "nginx": "nginx",
    "openssh": "openssh",
    "openssl": "openssl",
    "vsftpd": "vsftpd",
    "proftpd": "proftpd",
    "samba": "samba",
    "php": "php",
    "mysql": "oracle",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "iis": "microsoft",
    "microsoft iis": "microsoft",
    "tomcat": "apache",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
}

PRODUCT_MAP = {
    "apache httpd": "httpd",
    "httpd": "httpd",
    "postgres": "postgresql",
    "microsoft iis": "iis",
}


def _clean(part: str) -> str:
    part = (part or "").strip().lower()
    part = re.sub(r"\s+", "_", part)
    part = re.sub(r"[^a-z0-9_.~-]", "", part)
    return part or "*"


def canonicalize(
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    vendor: str | None = None,
) -> dict[str, str]:
    """Banner fields → canonical vendor/product/version + CPE 2.3."""
    raw_product = (product or service or "").strip()
    key = raw_product.lower()
    canon_vendor = _clean(vendor or VENDOR_MAP.get(key, raw_product))
    canon_product = _clean(PRODUCT_MAP.get(key, raw_product))
    canon_version = _clean(version or "") if version else "*"
    cpe = f"cpe:2.3:a:{canon_vendor}:{canon_product}:{canon_version}:*:*:*:*:*:*:*"
    return {
        "vendor": canon_vendor,
        "product": canon_product,
        "version": "" if canon_version == "*" else canon_version,
        "cpe": cpe,
    }


def correlate(
    service: str | None = None,
    product: str | None = None,
    version: str | None = None,
    vendor: str | None = None,
) -> dict[str, Any]:
    """CPE for a fingerprinted service + banner-aware CVE matches."""
    from schemas import Service
    from services.cve_lookup import CveDb

    canon = canonicalize(service, product, version, vendor)
    svc = Service(
        port=0, service=(service or product or "unknown").lower(), info=version or ""
    )
    matches = CveDb().match_service(
        svc,
        version=canon["version"] or None,
        product=canon["product"],
    )
    return {
        **canon,
        "matches": [
            {"id": m.get("id"), "severity": m.get("severity"), "title": m.get("title")}
            for m in matches
        ],
        "match_count": len(matches),
    }
