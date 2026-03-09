#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Sample Retriever
Downloads first-stage payloads from a given URL for offline analysis.
"""

import os
import re
import json
import hashlib
import logging
import argparse
from datetime import datetime, UTC
from urllib.parse import urljoin

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from playwright.sync_api import sync_playwright, Error as PlaywrightError

try:
    import pefile
except ImportError:
    pefile = None

DOWNLOAD_DIR = "malware_samples"
LOG_FILE = "retrieval_log.json"

BINARY_CONTENT_TYPES = {
    "application/octet-stream",
    "application/x-msdownload",
    "application/x-dosexec",
    "application/zip",
    "application/x-zip-compressed",
    "application/x-msi",
    "application/x-msi-installer",
    "application/vnd.ms-cab-compressed",
}

BINARY_EXTENSIONS = re.compile(
    r"\.(?:exe|dll|zip|msi|cab|vbs|js|bat|ps1|jar|7z|rar)(\?[^\s\"\']*)?$",
    re.IGNORECASE,
)

JS_REDIRECT_PATTERNS = [
    re.compile(r"""location\.replace\(["\']([^"\']+)["\']\)"""),
    re.compile(r"""location\.href\s*=\s*["\']([^"\']+)["\']\s*;"""),
    re.compile(r"""window\.location\s*=\s*["\']([^"\']+)["\']\s*;"""),
    re.compile(r"""content=["\']0;URL=([^"\']+)["\']""", re.IGNORECASE),
]

# Detects the fingerprint-gate POST pattern used by this dropper family:
# collects d/n/sp/su/iu/wd/hp and POSTs JSON to same URL before serving payload
FINGERPRINT_GATE_RE = re.compile(r"'d'\s*:\s*d,", re.DOTALL)

MIN_PAYLOAD_BYTES = 1_024
PAGE_WAIT_MS = 15_000

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

# Region profiles: IP + timezone must match the VPN exit node.
# d = -new Date().getTimezoneOffset() (minutes east of UTC, negated)
REGION_PROFILES = {
    "us-east":   {"d": -300, "n": "America/New_York"},
    "br":        {"d": -180, "n": "America/Sao_Paulo"},
    "mx":        {"d": -360, "n": "America/Mexico_City"},
    "ar":        {"d": -180, "n": "America/Argentina/Buenos_Aires"},
    "co":        {"d": -300, "n": "America/Bogota"},
    "cl":        {"d": -240, "n": "America/Santiago"},
    "pe":        {"d": -300, "n": "America/Lima"},
    "ec":        {"d": -300, "n": "America/Guayaquil"},
}

# PIA (Private Internet Access) VPN server names matching each region profile.
# These are the server location names as they appear in the PIA client.
PIA_SERVER_MAP = {
    "us-east":   "US East",
    "br":        "Brazil",
    "mx":        "Mexico",
    "ar":        "Argentina",
    "co":        "Colombia",
    "cl":        "Chile",
    "pe":        "Peru",
    "ec":        "Ecuador",
}


def build_fingerprint(region: str) -> dict:
    profile = REGION_PROFILES.get(region, REGION_PROFILES["us-east"])
    return {
        "d": profile["d"],
        "n": profile["n"],
        "sp": "Win32",
        "su": USER_AGENT,
        "iu": USER_AGENT,   # iframe UA must match parent or gate rejects
        "wd": False,
        "hp": "",
    }

HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


def make_session() -> requests.Session:
    session = requests.Session()
    session.headers.update(HEADERS)
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


# Magic byte -> extension map. Ordered: more specific signatures first.
MAGIC_SIGNATURES = [
    (b"MZ",           ".exe"),
    (b"PK\x03\x04",  ".zip"),
    (b"\xd0\xcf\x11\xe0", ".msi"),   # OLE2 composite (MSI/DOC/XLS)
    (b"MSCF",         ".cab"),
    (b"Rar!",         ".rar"),
    (b"7z\xbc\xaf",  ".7z"),
    (b"\x1f\x8b",    ".gz"),
    (b"%PDF",         ".pdf"),
]


def _detect_extension(data: bytes) -> str:
    for magic, ext in MAGIC_SIGNATURES:
        if data[:len(magic)] == magic:
            return ext
    return ".bin"


class MalwareRetriever:
    def __init__(self, region: str = "us-east", download_dir: str | None = None):
        self.download_dir = download_dir or DOWNLOAD_DIR
        os.makedirs(self.download_dir, exist_ok=True)
        self._seen: set[str] = set()
        self._session = make_session()
        self._region = region
        self._fingerprint = build_fingerprint(region)
        # Track files saved during a retrieve() call
        self._retrieved_files: list[dict] = []
        # Track all URLs encountered during retrieval (for IOCs)
        self._visited_urls: list[str] = []
        log.info("Region profile: %s (tz=%s, offset=%d)", region,
                 self._fingerprint["n"], self._fingerprint["d"])

    def _hash_bytes(self, data: bytes) -> tuple[str, str]:
        return (
            hashlib.md5(data).hexdigest(),
            hashlib.sha256(data).hexdigest(),
        )

    def _imphash(self, path: str) -> str | None:
        if not pefile:
            return None
        try:
            pe = pefile.PE(path)
            return pe.get_imphash()
        except pefile.PEFormatError:
            return None

    def _append_log(self, entry: dict) -> None:
        logs = []
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE, "r") as f:
                    logs = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                log.warning("Could not read log file, starting fresh: %s", e)
        logs.append(entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)

    def save_payload(self, data: bytes, url: str) -> dict | None:
        md5, sha256 = self._hash_bytes(data)
        if sha256 in self._seen:
            log.info("Skipping duplicate payload: %s", sha256[:16])
            return None
        self._seen.add(sha256)
        timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
        ext = _detect_extension(data)
        filename = f"sample_{timestamp}_{sha256[:8]}{ext}"
        path = os.path.join(self.download_dir, filename)
        with open(path, "wb") as f:
            f.write(data)
        imphash = self._imphash(path)
        entry = {
            "url": url,
            "path": path,
            "md5": md5,
            "sha256": sha256,
            "imphash": imphash,
            "size_bytes": len(data),
            "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        }
        self._append_log(entry)
        self._retrieved_files.append(entry)
        log.info("Payload saved : %s", path)
        log.info("SHA256        : %s", sha256)
        log.info("MD5           : %s", md5)
        if imphash:
            log.info("Imphash       : %s", imphash)
        return entry

    def _extract_js_redirects(self, html: str, base_url: str) -> list[str]:
        targets = []
        seen = set()
        for pattern in JS_REDIRECT_PATTERNS:
            for match in pattern.finditer(html):
                raw = match.group(1).replace("\\/" , "/")
                full = urljoin(base_url, raw)
                if full not in seen:
                    log.debug("JS redirect target: %s", full)
                    targets.append(full)
                    seen.add(full)
        return targets

    def _find_download_links(self, html: str, base_url: str) -> list[str]:
        candidates = re.findall(r'href=["\']([ ^"\' ]+)["\']', html, re.IGNORECASE)
        candidates += re.findall(r'src=["\']([ ^"\' ]+)["\']', html, re.IGNORECASE)
        links = []
        for href in candidates:
            if BINARY_EXTENSIONS.search(href) or re.search(r"/download/", href, re.IGNORECASE):
                full = urljoin(base_url, href)
                log.debug("Candidate link: %s", full)
                links.append(full)
        return links

    def _download_direct(self, url: str) -> bool:
        log.info("Direct download: %s", url)
        self._track_url(url)
        try:
            r = self._session.get(url, stream=True, timeout=60)
            r.raise_for_status()
            ct = r.headers.get("content-type", "").split(";")[0].strip()
            log.debug("Direct ct=%s len=%s", ct, r.headers.get("content-length", "?"))
            data = b"".join(r.iter_content(8192))
            if len(data) >= MIN_PAYLOAD_BYTES:
                self.save_payload(data, url)
                return True
            log.warning("Direct download too small (%d bytes)", len(data))
        except requests.RequestException as e:
            log.error("Direct download failed: %s", e)
        return False

    def _submit_fingerprint_gate(self, url: str, fingerprint: dict) -> bytes | None:
        """
        Replicate the fingerprint POST the dropper JS performs.
        The gate collects d/n/sp/su/iu/wd/hp and POSTs JSON to the same URL.
        The iu (iframe UA) field is what breaks headless browsers - both
        parent and iframe UA must match a real browser string.
        Returns the response body on success, None on failure.
        """
        log.info("Submitting fingerprint gate POST to: %s", url)
        self._track_url(url)
        post_headers = {
            **HEADERS,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": url.rsplit("/", 1)[0],
            "Referer": url,
        }
        form_data = {"d": json.dumps(fingerprint)}
        log.debug("Gate payload: %s", json.dumps(fingerprint))
        try:
            # Don't follow redirects - we need to inspect the POST response
            # headers (Location, Set-Cookie) before deciding next step
            r = self._session.post(
                url,
                data=form_data,
                headers=post_headers,
                timeout=30,
                allow_redirects=False,
            )
            log.debug("Gate POST status: %d", r.status_code)
            log.debug("Gate POST response headers: %s", dict(r.headers))
            log.debug("Gate POST cookies: %s", dict(self._session.cookies))

            # Follow redirect manually so session cookies carry over
            location = r.headers.get("location", "")
            if location:
                follow_url = urljoin(url, location)
                log.info("Gate redirected to: %s", follow_url)
                self._track_url(follow_url)
                f = self._session.get(follow_url, timeout=60, stream=True, allow_redirects=True)
                f.raise_for_status()
                log.debug("Follow response headers: %s", dict(f.headers))
                data = b"".join(f.iter_content(8192))
                log.debug("Follow response body (first 2000 bytes):\n%s",
                          data[:2000].decode("utf-8", errors="replace"))
                return data

            # No redirect - check if body contains the payload
            data = r.content
            log.debug("Gate response body (first 2000 bytes):\n%s",
                      data[:2000].decode("utf-8", errors="replace"))
            return data if data else None
        except requests.RequestException as e:
            log.error("Fingerprint gate POST failed: %s", e)
            return None

    def _fetch_and_parse(self, url: str, depth: int = 0) -> bool:
        if depth > 3:
            log.warning("JS redirect depth limit reached")
            return False

        log.info("Fetching [depth=%d]: %s", depth, url)
        self._track_url(url)
        try:
            r = self._session.get(url, timeout=30)
            r.raise_for_status()
        except requests.RequestException as e:
            log.warning("Fetch failed: %s", e)
            return False

        # Track the final URL after any HTTP redirects
        if r.url != url:
            self._track_url(r.url)

        ct = r.headers.get("content-type", "").split(";")[0].strip()
        log.debug("ct=%s len=%d url=%s", ct, len(r.content), r.url)

        if ct in BINARY_CONTENT_TYPES and len(r.content) >= MIN_PAYLOAD_BYTES:
            self.save_payload(r.content, r.url)
            return True

        log.debug("RAW HTML [%s]:\n%s", r.url, r.text[:5000])

        # Detect fingerprint gate and POST realistic browser data to bypass it
        if FINGERPRINT_GATE_RE.search(r.text):
            log.info("Fingerprint gate detected at: %s", r.url)
            gate_response = self._submit_fingerprint_gate(r.url, self._fingerprint)
            if gate_response and len(gate_response) >= MIN_PAYLOAD_BYTES:
                gate_ct = ""
                if gate_response[:2] == b"MZ":
                    gate_ct = "application/x-msdownload"
                elif gate_response[:4] == b"PK\x03\x04":
                    gate_ct = "application/zip"
                if gate_ct:
                    log.info("Gate returned binary (magic match: %s)", gate_ct)
                    self.save_payload(gate_response, r.url)
                    return True
                # Not a binary - may be HTML with a redirect to the actual file
                gate_html = gate_response.decode("utf-8", errors="replace")
                links = self._find_download_links(gate_html, r.url)
                for link in links:
                    if self._download_direct(link):
                        return True
                redirects = self._extract_js_redirects(gate_html, r.url)
                for target in redirects:
                    if self._fetch_and_parse(target, depth + 1):
                        return True
            return False

        # Follow JS redirects
        redirects = self._extract_js_redirects(r.text, r.url)
        for target in redirects:
            if self._fetch_and_parse(target, depth + 1):
                return True

        # Look for direct binary links
        links = self._find_download_links(r.text, r.url)
        captured = False
        for link in links:
            if self._download_direct(link):
                captured = True
        return captured

    def _try_playwright(self, url: str) -> bool:
        log.info("Falling back to Playwright for: %s", url)
        self._track_url(url)
        captured: list[tuple[bytes, str]] = []

        def handle_response(response):
            ct = response.headers.get("content-type", "").split(";")[0].strip()
            cd = response.headers.get("content-disposition", "")
            cl = response.headers.get("content-length", "?")
            log.debug("RESPONSE ct=%-40s cd=%-30s len=%-8s %s", ct, cd, cl, response.url)
            self._track_url(response.url)
            if ct not in BINARY_CONTENT_TYPES:
                return
            try:
                data = response.body()
            except PlaywrightError as e:
                log.warning("Could not read body from %s: %s", response.url, e)
                return
            if len(data) >= MIN_PAYLOAD_BYTES:
                captured.append((data, response.url))

        def handle_download(download):
            log.info("Download event: %s -> %s", download.url, download.suggested_filename)
            self._track_url(download.url)
            try:
                tmp = download.path()
                if tmp is None:
                    log.error("Download failed (no path returned): %s", download.url)
                    return
                with open(tmp, "rb") as f:
                    data = f.read()
                if len(data) >= MIN_PAYLOAD_BYTES:
                    captured.append((data, download.url))
                else:
                    log.warning("Download too small (%d bytes), skipping", len(data))
            except PlaywrightError as e:
                log.error("Download error for %s: %s", download.url, e)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                accept_downloads=True,
                user_agent=USER_AGENT,
                viewport={"width": 1920, "height": 1080},
                locale="en-US",
                timezone_id="America/New_York",
            )
            context.add_init_script(
                "Object.defineProperty(navigator, 'webdriver', {get: () => undefined})"
            )
            page = context.new_page()
            page.on("response", handle_response)
            context.on("download", handle_download)
            try:
                page.goto(url, timeout=60_000)
                page.wait_for_load_state("networkidle", timeout=30_000)
                rendered = page.content()
                log.debug("PAGE CONTENT [%s]:\n%s", page.url, rendered)
                links = self._find_download_links(rendered, page.url)
                for link in links:
                    log.info("Fetching link from rendered DOM: %s", link)
                    self._download_direct(link)
                page.wait_for_timeout(PAGE_WAIT_MS)
            except PlaywrightError as e:
                log.error("Navigation error: %s", e)
            finally:
                browser.close()

        for data, src_url in captured:
            self.save_payload(data, src_url)
        return bool(captured)

    def _track_url(self, url: str) -> None:
        """Record a URL encountered during retrieval (for IOC extraction)."""
        if url and url not in self._visited_urls:
            self._visited_urls.append(url)

    def check_current_location(self) -> dict:
        """
        Query external IP geolocation to determine the current VPN exit location.
        Compares against the target region to detect mismatches.

        Returns:
            Dictionary with:
                - ip (str): Current external IP
                - country (str): Country name
                - city (str): City name
                - timezone (str): Detected timezone (e.g. America/New_York)
                - target_timezone (str): Expected timezone for the selected region
                - match (bool): Whether detected timezone matches the target
                - pia_server (str): Which PIA server they should be on
                - error (str|None): Error message if lookup failed
        """
        target_profile = REGION_PROFILES.get(self._region, REGION_PROFILES["us-east"])
        target_tz = target_profile["n"]
        pia_server = PIA_SERVER_MAP.get(self._region, "US East")

        result = {
            "ip": "unknown",
            "country": "unknown",
            "city": "unknown",
            "timezone": "unknown",
            "target_timezone": target_tz,
            "match": False,
            "pia_server": pia_server,
            "error": None,
        }

        # Try ip-api.com first (no key required, returns timezone)
        for api_url in [
            "http://ip-api.com/json/?fields=query,country,city,timezone,status",
            "https://ipinfo.io/json",
        ]:
            try:
                r = requests.get(api_url, timeout=5)
                r.raise_for_status()
                data = r.json()

                if "ip-api" in api_url:
                    if data.get("status") != "success":
                        continue
                    result["ip"] = data.get("query", "unknown")
                    result["country"] = data.get("country", "unknown")
                    result["city"] = data.get("city", "unknown")
                    result["timezone"] = data.get("timezone", "unknown")
                else:
                    # ipinfo.io format
                    result["ip"] = data.get("ip", "unknown")
                    result["country"] = data.get("country", "unknown")
                    result["city"] = data.get("city", "unknown")
                    result["timezone"] = data.get("timezone", "unknown")

                result["match"] = result["timezone"] == target_tz
                log.info("Current location: %s, %s (tz=%s, ip=%s) — target: %s — %s",
                         result["city"], result["country"], result["timezone"],
                         result["ip"], target_tz,
                         "MATCH" if result["match"] else "MISMATCH")
                return result

            except Exception as e:
                log.debug("Geo-IP lookup failed for %s: %s", api_url, e)
                continue

        result["error"] = "Could not determine current location (geo-IP lookup failed)"
        log.warning(result["error"])
        return result

    def get_region_info(self) -> dict:
        """Return region profile info for VPN recommendation."""
        profile = REGION_PROFILES.get(self._region, REGION_PROFILES["us-east"])
        return {
            "region": self._region,
            "timezone": profile["n"],
            "utc_offset_minutes": profile["d"],
            "pia_server": PIA_SERVER_MAP.get(self._region, "US East"),
            "fingerprint": self._fingerprint,
        }

    def retrieve(self, url: str) -> dict:
        """
        Retrieve malware sample from URL.

        Returns:
            Dictionary with keys:
                - success (bool): Whether any payloads were captured
                - files (list[dict]): List of saved file entries (path, md5, sha256, etc.)
                - region_info (dict): Region/timezone profile used (for VPN recommendation)
                - url (str): The original URL
        """
        self._retrieved_files = []
        self._visited_urls = []
        log.info("Opening: %s", url)
        if not self._fetch_and_parse(url):
            if not self._try_playwright(url):
                log.warning("No binary payloads detected from either strategy")

        return {
            "success": len(self._retrieved_files) > 0,
            "files": list(self._retrieved_files),
            "region_info": self.get_region_info(),
            "url": url,
            "visited_urls": list(self._visited_urls),
        }


def main():
    parser = argparse.ArgumentParser(description="Malware Sample Retriever")
    parser.add_argument("url", help="URL to retrieve sample from")
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity (default: INFO)",
    )
    parser.add_argument(
        "--region",
        choices=["us-east", "br", "mx", "ar", "co", "cl", "pe", "ec"],
        default="us-east",
        help="Fingerprint region profile - must match your VPN exit node (default: us-east)",
    )
    args = parser.parse_args()
    logging.getLogger().setLevel(args.log_level)
    retriever = MalwareRetriever(region=args.region)
    retriever.retrieve(args.url)


if __name__ == "__main__":
    main()
