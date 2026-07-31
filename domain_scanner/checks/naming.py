"""Heuristics on the domain name itself."""

from __future__ import annotations

import math
import re
from collections import Counter

from ..models import CheckResult
from .base import ScanContext, register

VOWELS = set("aeiouy")


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_random(sld: str) -> bool:
    """Crude detector for machine-generated labels like ``x7kqp2vv``."""
    core = re.sub(r"[^a-z0-9]", "", sld.lower())
    if len(core) < 8:
        return False
    letters = [c for c in core if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(c in VOWELS for c in letters) / len(letters)
    entropy = shannon_entropy(core)
    longest_consonant_run = max(
        (len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", "".join(letters))),
        default=0,
    )
    return (vowel_ratio < 0.28 and entropy > 2.7) or longest_consonant_run >= 5


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


@register("naming", order=6, description="Domain-name heuristics", transport="none")
def check_naming(ctx: ScanContext) -> CheckResult:
    """Flag name patterns that attract automated review."""
    result = CheckResult(name="naming")
    sld = ctx.sld.lower()
    kw = ctx.config.keywords
    core = re.sub(r"[^a-z]", "", sld)

    hyphens = sld.count("-")
    digits = sum(c.isdigit() for c in sld)
    result.data = {
        "sld": sld,
        "length": len(sld),
        "hyphens": hyphens,
        "digits": digits,
        "entropy": round(shannon_entropy(sld), 2),
    }

    if hyphens >= 3:
        result.add("naming.many_hyphens", "medium",
                   f"{hyphens} hyphens in the name — typical of throwaway/spun domains",
                   {"hyphens": hyphens})
    elif hyphens == 2:
        result.add("naming.hyphens", "low", "2 hyphens in the name", {"hyphens": hyphens})

    if digits >= 4:
        result.add("naming.many_digits", "low",
                   f"{digits} digits in the name", {"digits": digits})

    if len(sld) > 25:
        result.add("naming.very_long", "low",
                   f"unusually long name ({len(sld)} chars)", {"length": len(sld)})

    if looks_random(sld):
        result.add("naming.random_looking", "medium",
                   "name looks machine-generated (low vowel ratio / high entropy)",
                   {"entropy": round(shannon_entropy(sld), 2)})

    if sld.startswith("xn--"):
        result.add("naming.punycode", "medium",
                   "internationalised (punycode) domain — a known homograph vector",
                   {"sld": sld})

    hits = {"sensitive": [], "scam_pattern": [], "brand": []}
    for bucket in hits:
        for word in kw.get(bucket, []):
            if word in sld:
                hits[bucket].append(word)

    # A brand's own domain is not impersonating anybody.
    official = kw.get("brand_domains", {})
    is_official = any(ctx.domain in official.get(b, []) for b in hits["brand"])
    result.data["keyword_hits"] = hits
    result.data["official_brand_domain"] = is_official

    if is_official:
        result.add("naming.official_brand", "info",
                   f"{ctx.domain} is the brand's own domain")
    elif hits["brand"]:
        result.add("naming.brand_lookalike", "high",
                   f"contains a frequently-impersonated brand name: {', '.join(hits['brand'])}",
                   {"matches": hits["brand"]})
    else:
        # Near-miss typosquats: edit distance 1-2 from a brand of similar length.
        near = []
        for brand in kw.get("brand", []):
            if abs(len(core) - len(brand)) <= 2 and len(brand) >= 5:
                if 0 < levenshtein(core, brand) <= 2:
                    near.append(brand)
        if near:
            result.data["typosquat_of"] = near
            result.add("naming.typosquat", "high",
                       f"one or two edits away from {', '.join(near[:3])} — reads as a typosquat",
                       {"matches": near})

    if hits["sensitive"]:
        result.add("naming.sensitive_vertical", "low",
                   f"names a restricted vertical: {', '.join(hits['sensitive'])}",
                   {"matches": hits["sensitive"]})

    if hits["scam_pattern"]:
        sev = "medium" if len(hits["scam_pattern"]) >= 2 else "low"
        result.add("naming.spammy_words", sev,
                   f"contains funnel/urgency wording: {', '.join(hits['scam_pattern'])}",
                   {"matches": hits["scam_pattern"]})

    if not result.findings:
        result.add("naming.clean", "info", "name reads as an ordinary brand")
    return result
