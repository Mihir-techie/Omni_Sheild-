"""Module 3 - account-takeover (ATO) velocity & anomaly engine (in-memory, process-local)."""

from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field

from app.shared.models import Finding, ModuleResult

_OS_RE = re.compile(r"windows|mac os x|android|iphone|ipad|linux|cros", re.I)
_BROWSER_RE = re.compile(r"edg|opr|chrome|firefox|safari|curl|python|okhttp", re.I)


class _BoundedSet:
    """Insertion-ordered set with a size cap (oldest dropped first)."""

    def __init__(self, cap: int = 25) -> None:
        self._d: OrderedDict[str, None] = OrderedDict()
        self._cap = cap

    def __contains__(self, item: str) -> bool:
        return item in self._d

    def __len__(self) -> int:
        return len(self._d)

    def add(self, item: str) -> None:
        self._d[item] = None
        self._d.move_to_end(item)
        while len(self._d) > self._cap:
            self._d.popitem(last=False)


@dataclass
class _Event:
    ts: float
    failed: int


@dataclass
class _UserState:
    events: deque[_Event] = field(default_factory=lambda: deque(maxlen=200))
    countries: _BoundedSet = field(default_factory=_BoundedSet)
    devices: _BoundedSet = field(default_factory=_BoundedSet)
    prefixes: _BoundedSet = field(default_factory=_BoundedSet)
    asns: _BoundedSet = field(default_factory=_BoundedSet)
    last_clean_country: str | None = None
    last_clean_ts: float = 0.0

    @property
    def has_baseline(self) -> bool:
        return bool(len(self.countries) or len(self.devices) or len(self.prefixes))


def device_fingerprint(user_agent: str | None) -> str | None:
    """Coarse browser/OS family so routine version bumps do not look like a new device."""
    if not user_agent:
        return None
    ua = user_agent.lower()
    os_m, br_m = _OS_RE.search(ua), _BROWSER_RE.search(ua)
    if not os_m and not br_m:
        return "unknown"
    return f"{br_m.group(0) if br_m else 'other'}/{os_m.group(0) if os_m else 'other'}"


def ip_prefix(ip: str | None) -> str | None:
    if not ip:
        return None
    addr = ipaddress.ip_address(ip)
    bits = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


class ATOEngine:
    def __init__(
        self,
        window_seconds: int = 300,
        max_users: int = 10_000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.window = window_seconds
        self.max_users = max_users
        self._clock = clock
        self._lock = threading.Lock()
        self._users: OrderedDict[str, _UserState] = OrderedDict()

    def analyze(
        self,
        username: str,
        failed_attempts: int = 0,
        ip: str | None = None,
        user_agent: str | None = None,
        country: str | None = None,
        asn: str | None = None,
    ) -> ModuleResult:
        now = self._clock()
        key = username.strip().casefold()
        country = country.upper() if country else None
        device = device_fingerprint(user_agent)
        prefix = ip_prefix(ip)
        asn = asn.strip().upper() if asn else None
        window_min = round(self.window / 60, 1)

        with self._lock:
            st = self._users.get(key)
            if st is None:
                st = self._users[key] = _UserState()
                while len(self._users) > self.max_users:
                    self._users.popitem(last=False)
            self._users.move_to_end(key)

            while st.events and st.events[0].ts < now - self.window:
                st.events.popleft()
            st.events.append(_Event(now, failed_attempts))
            failed_total = sum(e.failed for e in st.events)
            event_count = len(st.events)

            findings: list[Finding] = []
            if failed_total >= 25:
                pts = 60
            elif failed_total >= 10:
                pts = 40
            elif failed_total >= 5:
                pts = 20
            else:
                pts = 0
            if pts:
                findings.append(
                    Finding("failed_burst", pts, {"failed": failed_total, "window_min": window_min})
                )
            if event_count >= 15:
                findings.append(
                    Finding("rapid_requests", 10, {"events": event_count, "window_min": window_min})
                )

            notes: list[str] = []
            baseline = st.has_baseline
            if baseline:
                if country and st.countries and country not in st.countries:
                    findings.append(Finding("new_country", 25, {"country": country}))
                    if (
                        st.last_clean_country
                        and st.last_clean_country != country
                        and now - st.last_clean_ts < 3600
                    ):
                        findings.append(
                            Finding(
                                "impossible_travel",
                                40,
                                {
                                    "prev": st.last_clean_country,
                                    "country": country,
                                    "minutes": max(1, round((now - st.last_clean_ts) / 60)),
                                },
                            )
                        )
                if device and st.devices and device not in st.devices:
                    findings.append(Finding("new_device", 15, {"device": device}))
                if prefix and st.prefixes and prefix not in st.prefixes:
                    findings.append(Finding("new_network", 8, {"prefix": prefix}))
                if asn and st.asns and asn not in st.asns:
                    findings.append(Finding("new_asn", 12, {"asn": asn}))
            else:
                notes.append("No history for this account yet; baseline comparison skipped.")

            result = ModuleResult(
                "ato",
                findings,
                {
                    "window_seconds": self.window,
                    "failed_in_window": failed_total,
                    "events_in_window": event_count,
                    "baseline_ready": baseline,
                    "account_ref": hashlib.sha256(key.encode()).hexdigest()[:12],
                },
                notes,
            )

            # Only clean, low-risk events extend the baseline, so an attacker cannot "teach" it.
            if failed_attempts == 0 and result.score < 40:
                if country:
                    st.countries.add(country)
                    st.last_clean_country, st.last_clean_ts = country, now
                if device:
                    st.devices.add(device)
                if prefix:
                    st.prefixes.add(prefix)
                if asn:
                    st.asns.add(asn)
            return result
