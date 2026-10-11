#!/usr/bin/env python3
"""Manually check the public v1.2.7 installer on VirusTotal.

This script only processes the public, exact-hash pinned GitHub release asset.
It must never be reused for the private BHcmd beta or update packages.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DIGEST = "ba35c43324586fa001dc08c61b3241198b9b4768d7c7fc4158e06beebfe6cff6"
FILE = "trjacksongb.BitHeroesCommand-win-Setup.exe"
SOURCE = f"https://github.com/trjacksongb/BHcmd/releases/download/v1.2.7/{FILE}"
API = "https://www.virustotal.com/api/v3"
KEY = os.getenv("VIRUS_TOTAL")
REPORT = f"https://www.virustotal.com/gui/file/{DIGEST}"
SUMMARY = os.getenv("GITHUB_STEP_SUMMARY")


def summary(message: str) -> None:
    print(message, flush=True)
    if SUMMARY:
        with open(SUMMARY, "a", encoding="utf-8") as out:
            out.write(message + "\n")


def vt(method: str, endpoint: str) -> tuple[int, dict]:
    request = urllib.request.Request(
        endpoint if endpoint.startswith("https://") else API + endpoint,
        method=method,
        headers={"x-apikey": KEY, "accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        # Deliberately do not print request headers, account identifiers, or API responses.
        return error.code, {}


def stats(data: dict) -> str:
    attrs = data.get("data", {}).get("attributes", {})
    counts = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
    if not counts:
        return "Engine verdicts: not available yet"
    return "Engine verdicts: " + ", ".join(f"{key}={value}" for key, value in sorted(counts.items()))


def report(data: dict) -> None:
    attrs = data.get("data", {}).get("attributes", {})
    summary(f"- {stats(data)}")
    date = attrs.get("last_analysis_date")
    if isinstance(date, int):
        summary("- Last analysis: " + datetime.datetime.fromtimestamp(
            date, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"))
    threat = attrs.get("popular_threat_classification") or {}
    verdicts = attrs.get("sandbox_verdicts") or {}
    summary("- File type: " + str(attrs.get("type_description", "unknown"))[:80])
    summary("- Tags: " + ", ".join(str(t)[:80] for t in (attrs.get("tags") or [])[:15]))
    names = []
    for vendor, details in sorted(verdicts.items()):
        if not isinstance(details, dict):
            continue
        label = str(details.get("category", details.get("malware_classification", "unknown")))[:80]
        names.append(f"{str(vendor)[:60]}={label}")
    summary("- Sandbox verdicts provided: " + (", ".join(names) if names else "none"))
    if threat and isinstance(threat, dict):
        summary("- Community threat category: " + str(threat.get("suggested_threat_label", "not provided"))[:120])
    sig = attrs.get("signature_info") or {}
    if isinstance(sig, dict):
        summary("- Signature metadata: " + (", ".join(sorted(str(k) for k in sig.keys())[:12]) or "none"))
    engines = attrs.get("last_analysis_results") or {}
    for engine, details in sorted(engines.items()):
        if not isinstance(details, dict) or details.get("category") not in ("malicious", "suspicious"):
            continue
        category = str(details.get("category", "unknown"))[:30].replace("\\n", " ")
        result = str(details.get("result", "unspecified"))[:160].replace("\\n", " ")
        summary(f"- Flagged engine: {engine[:70]} — {category} — {result}")


def download(path: pathlib.Path) -> None:
    digest = hashlib.sha256()
    with urllib.request.urlopen(
        urllib.request.Request(SOURCE, headers={"User-Agent": "BHcmd-security-verification/1"}),
        timeout=120,
    ) as source, path.open("wb") as out:
        while chunk := source.read(1024 * 1024):
            out.write(chunk)
            digest.update(chunk)
    if digest.hexdigest() != DIGEST:
        path.unlink(missing_ok=True)
        raise RuntimeError("The GitHub release asset does not match the pinned SHA-256; upload blocked")
    summary("- Downloaded public v1.2.7 installer and verified its SHA-256")


def main() -> None:
    if not KEY:
        raise RuntimeError("Missing repository secret VIRUS_TOTAL")
    summary("## BHcmd v1.2.7 — VirusTotal verification")
    summary(f"- File: `{FILE}`")
    summary(f"- SHA-256: `{DIGEST}`")
    summary(f"- Report: {REPORT}")
    status, file_data = vt("GET", "/files/" + DIGEST)
    if status == 200:
        summary("- Status: Existing VirusTotal report found; no file upload required")
        report(file_data)
        return
    if status != 404:
        raise RuntimeError(f"VirusTotal hash lookup failed with HTTP {status}; no upload attempted")
    summary("- Hash not previously indexed by VirusTotal; submitting the explicitly public release")
    status, data = vt("GET", "/files/upload_url")
    if status != 200 or not isinstance(data.get("data"), str):
        raise RuntimeError(f"VirusTotal large-file upload URL unavailable (HTTP {status})")
    target = data["data"]
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme == "http" and parsed.hostname in ("www.virustotal.com", "virustotal.com"):
        target = urllib.parse.urlunparse(parsed._replace(scheme="https"))
        parsed = urllib.parse.urlparse(target)
    if parsed.scheme != "https" or parsed.hostname not in ("www.virustotal.com", "virustotal.com", "bigfiles.virustotal.com"):
        raise RuntimeError("VirusTotal returned an untrusted large-file upload URL host: " + str(parsed.hostname))
    with tempfile.TemporaryDirectory(prefix="bhcmd-vt-") as directory:
        path = pathlib.Path(directory) / FILE
        download(path)
        # Shell is never involved, response is collected, API key is never logged.
        cmd = [
            "curl", "--silent", "--show-error", "--fail-with-body",
            "--connect-timeout", "20", "--max-time", "360",
            "--header", "accept: application/json",
            "--header", "x-apikey: " + KEY,
            "--form", f"file=@{path};filename={FILE};type=application/octet-stream",
            target,
        ]
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=390)
        if result.returncode:
            raise RuntimeError(f"VirusTotal upload failed (curl exit {result.returncode}). "
                               "Account quotas or permissions may prevent large-file uploads.")
        try:
            submitted = json.loads(result.stdout)
            analysis_id = submitted["data"]["id"]
        except (KeyError, ValueError, TypeError) as e:
            raise RuntimeError("VirusTotal did not return a valid analysis identifier") from e
    summary("- Status: Public installer submitted to VirusTotal")
    summary("- Scan may take time to complete; results below reflect the latest available response")
    for attempt in range(9):
        if attempt:
            time.sleep(20)
        status, analysis = vt("GET", "/analyses/" + urllib.parse.quote(analysis_id, safe=""))
        if status == 200:
            state = analysis.get("data", {}).get("attributes", {}).get("status")
            if state == "completed":
                summary("- Analysis: completed")
                summary("- " + stats(analysis))
                status, latest = vt("GET", "/files/" + DIGEST)
                if status == 200:
                    report(latest)
                return
        elif status in (401, 403, 429):
            raise RuntimeError(f"VirusTotal analysis polling returned HTTP {status}")
    summary("- Analysis: still queued/in progress; check the linked report once indexing finishes")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        summary("- Verification could not complete: " + str(exc))
        raise SystemExit(1)
