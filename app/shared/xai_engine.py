"""Shared XAI & risk aggregator.

Takes raw module scores (0-100), weights and normalises them onto a single 0-100 scale, maps the
result to Safe -> Low -> Medium -> High -> Critical, and renders each triggered finding through a
rule-to-text template so the output reads as a plain-language business explanation.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from app.shared.models import ModuleResult

TIER_BOUNDS: tuple[tuple[int, str], ...] = (
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Safe"),
)

MODULE_WEIGHTS: dict[str, float] = {"phishing": 0.40, "deepfake": 0.30, "ato": 0.30}
MODULE_LABELS: dict[str, str] = {
    "phishing": "phishing / malicious-link",
    "deepfake": "synthetic-media",
    "ato": "account-takeover",
}
DECISIONS: dict[str, str] = {
    "Safe": "allow",
    "Low": "allow",
    "Medium": "review",
    "High": "block",
    "Critical": "block",
}

# A strong signal in one module must not be diluted away by clean results in the others.
PEAK_FLOOR = 0.85

LEADS: dict[str, str] = {
    "Safe": "No significant {label} indicators were found.",
    "Low": "A few minor {label} indicators were found; the risk is low.",
    "Medium": "Several {label} indicators were found; this warrants a manual review.",
    "High": "Strong {label} indicators were found; treat this as high-risk until verified.",
    "Critical": "Severe {label} indicators were found; escalate immediately.",
}

ACTIONS: dict[str, dict[str, str]] = {
    "phishing": {
        "allow": "No action needed; keep normal vigilance.",
        "review": "Do not enter credentials; have security staff verify the link before allowing it.",
        "block": "Block the link, quarantine the message that contained it and warn recipients.",
    },
    "deepfake": {
        "allow": "No action needed; this result is a weak signal, not proof of authenticity.",
        "review": "Do not rely on this media alone; request a live re-verification such as a "
        "liveness check or a call-back on a known number.",
        "block": "Hold the submission and escalate to a trained analyst for manual verification.",
    },
    "ato": {
        "allow": "No action needed.",
        "review": "Require step-up authentication (OTP or passkey) before continuing the session.",
        "block": "Lock the session, force a password reset and notify the account owner.",
    },
}

TEMPLATES: dict[str, str] = {
    # --- phishing ---
    "ip_host": "The link uses a raw IP address ({host}) instead of a domain name, which "
    "legitimate services rarely do.",
    "at_symbol": "The URL contains an '@' character, a trick used to hide the real destination.",
    "no_https": "The link is not encrypted (plain HTTP), so anything typed into it can be "
    "intercepted.",
    "long_url": "The URL is unusually long ({length} characters), which is often used to hide the "
    "real destination.",
    "deep_subdomains": "The address has {count} subdomain levels, a pattern used to make a fake "
    "site look official.",
    "many_hyphens": "The domain name contains {count} hyphens, common in throwaway look-alike "
    "domains.",
    "punycode": "The domain uses internationalised (punycode) characters, which can imitate "
    "familiar names with look-alike letters.",
    "suspicious_keywords": "The URL contains account-related keywords ({keywords}) often used in "
    "credential-theft pages.",
    "risky_tld": "The domain ends in '.{tld}', an extension disproportionately used for abusive "
    "sites.",
    "url_shortener": "The link goes through a URL shortener ({host}), which hides its final "
    "destination.",
    "nonstandard_port": "The link uses a non-standard port ({port}).",
    "typosquat": "The domain '{domain}' looks like a misspelling of the {brand} brand, a "
    "typosquatting pattern.",
    "brand_misplaced": "The name '{brand}' appears in the address, but the site is not an "
    "official {brand} domain ({domain}).",
    "intent_urgency": "The message uses urgency or threat language ({phrases}).",
    "intent_credential": "The message asks for sensitive details ({phrases}).",
    # --- deepfake ---
    "spectral_peaks": "The image's frequency spectrum has unusually strong periodic peaks "
    "({peak_pct}% of analysed frequencies), a pattern sometimes left by generative-model "
    "upsampling.",
    "hf_energy_anomaly": "The image's fine-detail (high-frequency) energy is {direction} for a "
    "camera photo (ratio {hf_ratio}).",
    "smooth_blend_boundaries": "Smooth, texture-free regions meet sharp detail abruptly across "
    "{pct}% of the image grid, which can indicate blended or retouched areas.",
    "wav_vocoder_cutoff": "The audio drops sharply by {drop_db} dB near {cutoff_khz} kHz, a "
    "cutoff pattern typical of some neural voice generators.",
    "wav_bandlimited": "The audio is sharply band-limited near {cutoff_khz} kHz ({drop_db} dB "
    "drop); this is also common in compressed phone or MP3 audio.",
    # --- account takeover ---
    "failed_burst": "{failed} failed sign-in attempts occurred within {window_min} minutes, "
    "consistent with password guessing.",
    "rapid_requests": "{events} authentication events arrived within {window_min} minutes, much "
    "faster than normal user behaviour.",
    "new_country": "Sign-in came from {country}, a country not seen in this account's history.",
    "new_device": "Sign-in came from a device/browser ({device}) not previously seen for this "
    "account.",
    "new_network": "Sign-in came from a new network ({prefix}) for this account.",
    "new_asn": "Sign-in came from a new network provider ({asn}) for this account.",
    "impossible_travel": "The account signed in from {prev} and then from {country} only "
    "{minutes} minutes later, which is physically implausible.",
}


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return "?"


def _fmt(value: Any) -> str:
    if isinstance(value, (list, tuple, set)):
        value = ", ".join(str(v) for v in value)
    text = str(value)
    return text if len(text) <= 100 else text[:97] + "..."


def render_finding(code: str, params: dict[str, Any]) -> str:
    template = TEMPLATES.get(code, "Indicator '{code}' was triggered.")
    data = _SafeDict({k: _fmt(v) for k, v in params.items()})
    data.setdefault("code", code)
    return template.format_map(data)


def tier_for(score: int) -> str:
    for floor, name in TIER_BOUNDS:
        if score >= floor:
            return name
    return "Safe"


@dataclass
class ExplainedFinding:
    module: str
    code: str
    points: int
    explanation: str


@dataclass
class RiskReport:
    score: int
    tier: str
    decision: str
    module_scores: dict[str, int]
    findings: list[ExplainedFinding]
    summary: str
    recommended_action: str


def aggregate(results: Sequence[ModuleResult]) -> RiskReport:
    """Weight, normalise and explain one or more module results."""
    if not results:
        raise ValueError("aggregate() needs at least one module result")

    scores = {r.module: r.score for r in results}
    total_weight = sum(MODULE_WEIGHTS.get(m, 0.3) for m in scores)
    weighted = sum(MODULE_WEIGHTS.get(m, 0.3) * s for m, s in scores.items()) / total_weight
    final = max(0, min(100, round(max(weighted, PEAK_FLOOR * max(scores.values())))))
    tier = tier_for(final)
    decision = DECISIONS[tier]

    findings = sorted(
        (
            ExplainedFinding(r.module, f.code, f.points, render_finding(f.code, f.params))
            for r in results
            for f in r.findings
            if f.points > 0
        ),
        key=lambda f: f.points,
        reverse=True,
    )

    top_module = max(scores, key=scores.get)
    label = (
        MODULE_LABELS.get(top_module, top_module)
        if len(scores) == 1
        else "combined security"
    )
    summary = f"Risk is {tier} ({final}/100). " + LEADS[tier].format(label=label)
    if findings:
        drivers = " ".join(f.explanation for f in findings[:3])
        summary += f" Main drivers: {drivers}"

    action = ACTIONS.get(top_module, ACTIONS["phishing"])[decision]
    return RiskReport(
        score=final,
        tier=tier,
        decision=decision,
        module_scores=scores,
        findings=findings,
        summary=summary,
        recommended_action=action,
    )
