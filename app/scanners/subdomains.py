from __future__ import annotations

import logging
from typing import Any
import httpx

logger = logging.getLogger(__name__)

CRTSH_URL = "https://crt.sh/"


async def scan_subdomains(
    domain: str,
    *,
    client: httpx.AsyncClient | None = None,
    timeout: float = 10.0,
) -> list[str]:
    """Passively discover subdomains using public Certificate Transparency logs via crt.sh.

    Does not send any packets or connections to the target domain or its hosts.
    """
    normalized_domain = domain.strip().lower().lstrip(".")
    params = {"q": f"%.{normalized_domain}", "output": "json"}
    headers = {"User-Agent": "SecuScan-API/1.0 (+https://github.com/h3n-x/secuscan-api)"}

    owns_client = client is None
    http_client = client or httpx.AsyncClient(timeout=timeout, follow_redirects=True)

    try:
        response = await http_client.get(CRTSH_URL, params=params, headers=headers)
        if response.status_code != 200:
            logger.warning("crt.sh responded with non-200 status: %s", response.status_code)
            return []

        data = response.json()
        if not isinstance(data, list):
            return []

        subdomains: set[str] = set()
        for item in data:
            if not isinstance(item, dict):
                continue
            name_value = item.get("name_value")
            if not isinstance(name_value, str):
                continue

            # Split multi-domain certificates (separated by newline)
            for raw_name in name_value.splitlines():
                clean_name = raw_name.strip().lower()
                if clean_name.startswith("*."):
                    clean_name = clean_name[2:]

                # Only include valid subdomains of the target domain
                if clean_name == normalized_domain or clean_name.endswith(f".{normalized_domain}"):
                    subdomains.add(clean_name)

        return sorted(subdomains)
    except (httpx.HTTPError, ValueError, Exception) as exc:
        logger.warning("Failed to query crt.sh for %s: %s", domain, exc)
        return []
    finally:
        if owns_client:
            await http_client.aclose()
