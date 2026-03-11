"""Shared API GET helper for network-audit.io."""

import requests


def api_get(api_url, api_key, path, params=None):
    """GET a network-audit.io API endpoint.

    Args:
        api_url: Base API URL (no trailing slash).
        api_key: API key for X-API-Key header.
        path: URL path (e.g. "/api/v1/account").
        params: Optional query parameters dict.

    Returns:
        Parsed JSON dict on 200, or an error string.
    """
    try:
        resp = requests.get(
            f"{api_url}{path}",
            headers={"X-API-Key": api_key},
            params=params,
            timeout=15,
        )
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return "Not Found"
        if resp.status_code == 429:
            return "Rate Limited"
        return f"API Error ({resp.status_code})"
    except requests.RequestException as e:
        return f"API Error ({e})"
