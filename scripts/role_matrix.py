#!/usr/bin/env python3
"""Build and conservatively evaluate role/object authorization matrices.

Inputs contain role labels and opaque object references only. Credentials and
HTTP execution remain in the existing API/web testers; a status code alone can
produce a candidate, never a confirmed cross-role data-access result.
"""
import re

_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_. -]{0,79}$")
_OBJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,159}$")


class RoleMatrixError(ValueError):
    """Malformed role or ownership matrix."""


def build_matrix(roles, objects):
    """Return a role-by-object plan based only on explicitly declared policy."""
    if not isinstance(roles, list) or not roles or len(roles) > 32:
        raise RoleMatrixError("roles must contain 1 to 32 declared identities")
    role_names = []
    for role in roles:
        name = role.get("name") if isinstance(role, dict) else role
        if not isinstance(name, str) or not _LABEL.fullmatch(name.strip()):
            raise RoleMatrixError("each role needs a short, valid label")
        role_names.append(name.strip())
    if len(set(role_names)) != len(role_names):
        raise RoleMatrixError("role labels must be unique")
    if not isinstance(objects, list) or len(objects) > 1000:
        raise RoleMatrixError("objects must be a list of at most 1000 entries")
    rows, seen = [], set()
    for item in objects:
        if not isinstance(item, dict):
            raise RoleMatrixError("each object must be an object")
        object_id, owner, allowed = item.get("id"), item.get("owner_role"), item.get("allowed_roles")
        if not isinstance(object_id, str) or not _OBJECT.fullmatch(object_id):
            raise RoleMatrixError("object ids must be opaque bounded identifiers")
        if object_id in seen:
            raise RoleMatrixError("object ids must be unique")
        if owner not in role_names:
            raise RoleMatrixError("each object owner must be a declared role")
        if not isinstance(allowed, list) or any(not isinstance(role, str) for role in allowed):
            raise RoleMatrixError("allowed_roles must be explicit; no policy is inferred")
        if len(set(allowed)) != len(allowed) or any(role not in role_names for role in allowed):
            raise RoleMatrixError("allowed_roles must contain unique declared role labels")
        if owner not in allowed:
            raise RoleMatrixError("owner role must be explicitly listed as allowed")
        for actor in role_names:
            rows.append({"role": actor, "object_id": object_id,
                         "owner_role": owner, "expected_access": actor in allowed,
                         "status": "planned"})
        seen.add(object_id)
    return rows


def evaluate_matrix(matrix, observations):
    """Compare observed results with declared policy and separate candidates from proof."""
    if not isinstance(matrix, list) or not isinstance(observations, list):
        raise RoleMatrixError("matrix and observations must be lists")
    observed_by_key = {}
    for result in observations:
        if not isinstance(result, dict):
            continue
        role, object_id = result.get("role"), result.get("object_id")
        if not isinstance(role, str) or not isinstance(object_id, str):
            continue
        observed_by_key.setdefault((role, object_id), []).append(result)
    evaluated = []
    for planned in matrix:
        key = (planned["role"], planned["object_id"])
        result = observed_by_key.get(key, [])
        if not result:
            evaluated.append(dict(planned, status="untested"))
            continue
        sample = result[-1]
        access = sample.get("access")
        if access not in ("allowed", "denied", "error"):
            status = "inconclusive"
        elif planned["expected_access"] and access == "allowed":
            status = "expected_access"
        elif planned["expected_access"] and access == "denied":
            status = "unexpected_denial"
        elif not planned["expected_access"] and access == "denied":
            status = "expected_denial"
        elif access == "error":
            status = "inconclusive"
        else:
            status = "confirmed_violation" if all(sample.get(field) is True for field in (
                "role_identity_verified", "owner_control_passed", "object_identity_verified",
                "unauthorized_data_proof")) else "candidate_violation"
        evaluated.append(dict(planned, status=status))
    counts = {status: sum(row["status"] == status for row in evaluated) for status in (
        "confirmed_violation", "candidate_violation", "expected_access", "expected_denial",
        "unexpected_denial", "inconclusive", "untested")}
    counts["total"] = len(evaluated)
    return {"counts": counts, "cases": evaluated,
            "confirmation_requires": ["role_identity_verified", "owner_control_passed",
                                       "object_identity_verified", "unauthorized_data_proof"]}
