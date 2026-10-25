import hashlib
import ipaddress
import os
import re
from typing import Any
from urllib.parse import urlparse

import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

load_dotenv()
app = FastAPI(title="Cyber-Pass Threat Intelligence API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:8000"],
    allow_credentials=False, allow_methods=["GET", "POST"], allow_headers=["*"],
)
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
OTX_API_KEY = os.getenv("OTX_API_KEY", "").strip()
TIMEOUT = httpx.Timeout(12.0, connect=5.0)


class LookupRequest(BaseModel):
    indicator: str = Field(min_length=1, max_length=2048)


def classify_indicator(value: str) -> tuple[str, str]:
    value = value.strip()
    if not value or any(ord(c) < 32 for c in value):
        raise HTTPException(status_code=400, detail="Invalid indicator.")
    if len(value) > 2048:
        raise HTTPException(status_code=400, detail="Indicator is too long.")
    try:
        ipaddress.ip_address(value)
        return "ip", value
    except ValueError:
        pass
    if re.fullmatch(r"(?i)[a-f0-9]{32}", value):
        return "hash_md5", value.lower()
    if re.fullmatch(r"(?i)[a-f0-9]{40}", value):
        return "hash_sha1", value.lower()
    if re.fullmatch(r"(?i)[a-f0-9]{64}", value):
        return "hash_sha256", value.lower()
    if "://" in value:
        parsed = urlparse(value)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise HTTPException(status_code=400, detail="Only valid HTTP/HTTPS URLs are supported.")
        return "url", value
    # Domain: validate conservatively; do not resolve or fetch user-supplied URLs.
    domain = value.rstrip(".").lower()
    if len(domain) <= 253 and "." in domain and all(
        re.fullmatch(r"(?=.{1,63}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", part)
        for part in domain.split(".")
    ):
        return "domain", domain
    raise HTTPException(status_code=400, detail="Enter a valid IP, domain, HTTP/HTTPS URL, or MD5/SHA-1/SHA-256 hash.")


async def vt_lookup(kind: str, value: str) -> dict[str, Any]:
    if not VT_API_KEY:
        return {"name": "VirusTotal", "status": "NOT CONFIGURED", "summary": "Set VIRUSTOTAL_API_KEY in backend/.env to enable this source.", "malicious": None, "evidence": []}
    if kind == "ip":
        endpoint = f"https://www.virustotal.com/api/v3/ip_addresses/{value}"
    elif kind == "domain":
        endpoint = f"https://www.virustotal.com/api/v3/domains/{value}"
    elif kind == "url":
        url_id = __import__("base64").urlsafe_b64encode(value.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint = f"https://www.virustotal.com/api/v3/files/{value}"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(endpoint, headers={"x-apikey": VT_API_KEY})
        if response.status_code == 404:
            return {"name": "VirusTotal", "status": "NO RECORD", "summary": "No record found for this indicator.", "malicious": None, "evidence": []}
        if response.status_code == 429:
            return {"name": "VirusTotal", "status": "RATE LIMITED", "summary": "Provider rate limit reached. Try again later.", "malicious": None, "evidence": []}
        if response.status_code in (401, 403):
            return {"name": "VirusTotal", "status": "AUTH ERROR", "summary": "API key rejected or access not permitted.", "malicious": None, "evidence": []}
        response.raise_for_status()
        body = response.json().get("data", {}).get("attributes", {})
        stats = body.get("last_analysis_stats", {})
        malicious = int(stats.get("malicious", 0) or 0)
        suspicious = int(stats.get("suspicious", 0) or 0)
        total = sum(int(stats.get(k, 0) or 0) for k in ("malicious", "suspicious", "harmless", "undetected", "timeout"))
        evidence = [f"VirusTotal detections: {malicious} malicious and {suspicious} suspicious out of {total} reported engines."]
        rep = body.get("reputation")
        if rep is not None:
            evidence.append(f"Community reputation score: {rep}.")
        return {"name": "VirusTotal", "status": "SUCCESS", "summary": f"{malicious} malicious · {suspicious} suspicious · {total} engines reported", "malicious": malicious, "suspicious": suspicious, "evidence": evidence}
    except (httpx.TimeoutException, httpx.RequestError):
        return {"name": "VirusTotal", "status": "UNAVAILABLE", "summary": "Network or timeout error while contacting provider.", "malicious": None, "evidence": []}
    except httpx.HTTPStatusError as exc:
        return {"name": "VirusTotal", "status": f"HTTP {exc.response.status_code}", "summary": "Provider returned an error.", "malicious": None, "evidence": []}


async def otx_lookup(kind: str, value: str) -> dict[str, Any]:
    if not OTX_API_KEY:
        return {"name": "AlienVault OTX", "status": "NOT CONFIGURED", "summary": "Set OTX_API_KEY in backend/.env to enable this source.", "pulses": None, "evidence": []}
    if kind == "ip":
        family = "IPv6" if ":" in value else "IPv4"
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{family}/{value}/general"
    elif kind == "domain":
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/domain/{value}/general"
    elif kind == "url":
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{value}/general"
    else:
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/file/{value}/general"
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(endpoint, headers={"X-OTX-API-KEY": OTX_API_KEY})
        if response.status_code == 404:
            return {"name": "AlienVault OTX", "status": "NO RECORD", "summary": "No record found for this indicator.", "pulses": 0, "evidence": []}
        if response.status_code == 429:
            return {"name": "AlienVault OTX", "status": "RATE LIMITED", "summary": "Provider rate limit reached. Try again later.", "pulses": None, "evidence": []}
        if response.status_code in (401, 403):
            return {"name": "AlienVault OTX", "status": "AUTH ERROR", "summary": "API key rejected or access not permitted.", "pulses": None, "evidence": []}
        response.raise_for_status()
        body = response.json()
        count = int(body.get("pulse_info", {}).get("count", 0) or 0)
        evidence = [f"AlienVault OTX reports {count} pulse(s) associated with this indicator."]
        pulses = body.get("pulse_info", {}).get("pulses", []) or []
        for pulse in pulses[:3]:
            name = pulse.get("name")
            if name:
                evidence.append(f"Related pulse: {str(name)[:180]}.")
        return {"name": "AlienVault OTX", "status": "SUCCESS", "summary": f"{count} related threat-intelligence pulse(s)", "pulses": count, "evidence": evidence}
    except (httpx.TimeoutException, httpx.RequestError):
        return {"name": "AlienVault OTX", "status": "UNAVAILABLE", "summary": "Network or timeout error while contacting provider.", "pulses": None, "evidence": []}
    except httpx.HTTPStatusError as exc:
        return {"name": "AlienVault OTX", "status": f"HTTP {exc.response.status_code}", "summary": "Provider returned an error.", "pulses": None, "evidence": []}


@app.get("/api/health")
async def health():
    return {"status": "ok", "virustotal_configured": bool(VT_API_KEY), "otx_configured": bool(OTX_API_KEY)}


@app.post("/api/lookup")
async def lookup(request: LookupRequest):
    kind, indicator = classify_indicator(request.indicator)
    import asyncio
    vt, otx = await asyncio.gather(vt_lookup(kind, indicator), otx_lookup(kind, indicator))
    sources = [vt, otx]
    evidence = [line for source in sources for line in source.get("evidence", [])]
    vt_malicious = vt.get("malicious")
    vt_suspicious = vt.get("suspicious")
    otx_pulses = otx.get("pulses")
    configured_results = [s for s in sources if s["status"] == "SUCCESS"]
    if (vt_malicious or 0) > 0 or (vt_suspicious or 0) > 0 or (otx_pulses or 0) >= 3:
        risk = "HIGH" if (vt_malicious or 0) >= 3 or (otx_pulses or 0) >= 5 else "MEDIUM"
    elif configured_results:
        risk = "LOW"
    else:
        risk = "UNKNOWN"
    if not configured_results:
        evidence.append("No configured provider returned usable results. Risk is UNKNOWN, not safe.")
    elif risk == "LOW":
        evidence.append("No strong threat signal was returned by the configured sources in this lookup. This is not proof of safety.")
    return {
        "indicator": indicator, "type": kind.upper(), "risk": risk,
        "sources": [{"name": s["name"], "status": s["status"], "summary": s["summary"]} for s in sources],
        "evidence": evidence,
        "note": "Assessment is a simple heuristic based on available provider results, not a definitive verdict. Provider coverage, rate limits, and freshness vary. Treat unknown as unknown, not clean."
    }
