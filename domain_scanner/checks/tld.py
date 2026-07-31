"""TLD reputation tier."""

from __future__ import annotations

from ..models import CheckResult
from .base import ScanContext, register

TIER_SEVERITY = {0: None, 1: None, 2: "low", 3: "medium"}


def tier_for(suffix: str, tld_risk: dict) -> int:
    tiers = tld_risk.get("tiers", {})
    for tier_name, entries in tiers.items():
        if suffix in entries:
            return int(tier_name)
    # A multi-label suffix we do not know: fall back to its last label.
    if "." in suffix:
        return tier_for(suffix.rsplit(".", 1)[-1], tld_risk)
    return int(tld_risk.get("default_tier", 2))


@register("tld", order=5, description="TLD abuse-rate tier", transport="none")
def check_tld(ctx: ScanContext) -> CheckResult:
    """Rate the top-level domain by its published abuse rate."""
    result = CheckResult(name="tld")
    tier = tier_for(ctx.suffix, ctx.config.tld_risk)
    notes = ctx.config.tld_risk.get("tier_notes", {})
    result.data = {
        "suffix": ctx.suffix,
        "tier": tier,
        "note": notes.get(str(tier), ""),
    }
    severity = TIER_SEVERITY.get(tier)
    if severity:
        result.add(
            "tld.high_abuse" if tier == 3 else "tld.elevated",
            severity,
            f".{ctx.suffix} is a tier-{tier} TLD ({'high' if tier == 3 else 'elevated'} abuse rate)",
            {"tier": tier, "note": notes.get(str(tier), "")},
        )
    else:
        result.add("tld.ok", "info", f".{ctx.suffix} is a low-abuse TLD (tier {tier})", {"tier": tier})
    return result
