import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import List, Optional

SETUP_CDN_BASE = "https://setup.rbxcdn.com"


@dataclass
class DeployEntry:
    version_hash: str
    binary_type: str  # e.g. Studio64, WindowsPlayer, Studio
    timestamp_raw: str
    version_number: str


class SetupFetcher:
    """Fetches deployment history and binary hashes from Roblox setup CDN."""

    def __init__(self, base_url: str = SETUP_CDN_BASE, timeout: float = 20.0):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.user_agent = "Roblox/WinINet (roblox-pe inspection tool)"

    def _url_for(self, endpoint: str, channel: Optional[str] = None) -> str:
        ep = endpoint.lstrip("/")
        if channel and channel.lower() not in ("live", "production"):
            return f"{self.base_url}/channel/{channel.lower()}/{ep}"
        return f"{self.base_url}/{ep}"

    def _request(self, endpoint: str, channel: Optional[str] = None) -> str:
        url = self._url_for(endpoint, channel)
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as err:
            # Roblox returns 403 on invalid channel names or expired builds
            raise RuntimeError(f"HTTP {err.code} fetching {url}") from err
        except urllib.error.URLError as err:
            raise RuntimeError(f"Network error fetching {url}: {err.reason}") from err

    def fetch_deploy_history(self, channel: Optional[str] = None) -> str:
        return self._request("DeployHistory.txt", channel=channel)

    def get_latest_version_hash(
        self, binary_type: str = "Studio64", channel: Optional[str] = None
    ) -> Optional[str]:
        # Studio x64 uses versionQTStudio on live; 64-bit player uses version-64bit
        norm = binary_type.lower()
        if norm in ("studio64", "studio"):
            endpoint = "versionQTStudio"
        elif norm in ("player64", "windowsplayer64", "player"):
            endpoint = "version-64bit"
        elif norm in ("player32", "windowsplayer32"):
            endpoint = "version"
        else:
            endpoint = "versionQTStudio"

        try:
            raw = self._request(endpoint, channel=channel).strip()
        except RuntimeError:
            return None

        if raw.startswith("version-"):
            return raw
        return None

    def get_binary_url(self, version_hash: str, filename: str, channel: Optional[str] = None) -> str:
        return self._url_for(f"{version_hash}-{filename}", channel=channel)

    def parse_deploy_history(self, text: Optional[str] = None, channel: Optional[str] = None) -> List[DeployEntry]:
        if text is None:
            text = self.fetch_deploy_history(channel=channel)

        entries: List[DeployEntry] = []

        # Regex matches entries like:
        # New Studio64 version-d0a51c964fd64cf6 at 10/24/2023 4:12:15 PM, file version: 0. 599. 0. 5990528...
        line_re = re.compile(
            r"New\s+(\w+)\s+(version-[a-f0-9]+)\s+at\s+([^,]+),\s+file version:\s*([0-9.,\s]+)",
            re.IGNORECASE,
        )

        for line in text.splitlines():
            line = line.strip()
            if not line or not line.startswith("New"):
                continue
            # print(f"DEBUG: raw line: {line}")
            m = line_re.search(line)
            if m:
                btype, vhash, ts, fver = m.groups()
                clean_fver = re.sub(r"\s+", "", fver).rstrip(".")
                entries.append(
                    DeployEntry(
                        version_hash=vhash,
                        binary_type=btype,
                        timestamp_raw=ts.strip(),
                        version_number=clean_fver,
                    )
                )

        # FIXME: deploy history can contain out-of-order rollbacks; we keep CDN order for now
        return entries
