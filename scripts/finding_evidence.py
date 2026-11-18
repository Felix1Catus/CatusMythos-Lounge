#!/usr/bin/env python3
"""Shared, conservative evidence-quality checks for normalized findings.

This module never promotes a finding by itself. It reports whether a tool's
existing validation claim has the declared baseline, negative control, effect,
reproduction, and impact evidence needed for an independently reviewable proof.
"""

MAX_IMPACT_ITEMS = 20
MAX_IMPACT_LENGTH = 500


def evaluate_proof(proof):
    """Check a bounded proof record and return booleans only, never raw evidence."""
    proof = proof if isinstance(proof, dict) else {}
    checks = {
        "baseline_observed": proof.get("baseline_observed") is True,
        "negative_control_rejected": proof.get("negative_control_rejected") is True,
        "effect_observed": proof.get("effect_observed") is True,
        "reproduced": proof.get("reproduced") is True,
    }
    impact = proof.get("impact_evidence", [])
    if not isinstance(impact, list):
        impact = []
    safe_impact_count = sum(1 for item in impact[:MAX_IMPACT_ITEMS]
                            if isinstance(item, str) and 0 < len(item.strip()) <= MAX_IMPACT_LENGTH)
    checks["impact_evidence_present"] = safe_impact_count > 0
    checks["complete"] = all(checks.values())
    checks["impact_evidence_count"] = safe_impact_count
    return checks


def review_finding(finding):
    """Attach a non-authoritative lifecycle/evidence review to a finding."""
    finding = finding if isinstance(finding, dict) else {}
    finding_type = str(finding.get("type", "")).lower()
    validated = finding.get("validated")
    confidence = str(finding.get("confidence", "")).strip().lower()
    if validated is False or "candidate" in finding_type or confidence in ("low", "tentative", "candidate"):
        state = "candidate"
    elif validated is True:
        state = "confirmed" if evaluate_proof(finding.get("proof"))["complete"] else "validated_needs_proof_review"
    else:
        state = "unverified"
    proof_checks = evaluate_proof(finding.get("proof"))
    return {
        "schema_version": 1,
        "assessment_state": state,
        "source_validation_claim": validated if isinstance(validated, bool) else None,
        "proof_checks": proof_checks,
        "promotion_performed": False,
        "limitations": "This review summarizes supplied evidence metadata; it does not independently replay requests.",
    }
