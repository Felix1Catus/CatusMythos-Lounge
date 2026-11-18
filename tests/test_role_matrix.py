"""Offline tests for role/object authorization planning and proof thresholds."""
import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("role_matrix", ROOT / "scripts" / "role_matrix.py")
matrix_module = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(matrix_module)


class RoleMatrixTests(unittest.TestCase):
    def setUp(self):
        self.roles = [{"name": "anonymous"}, {"name": "member"}, {"name": "manager"}]
        self.objects = [{"id": "invoice-42", "owner_role": "member", "allowed_roles": ["member", "manager"]}]
        self.matrix = matrix_module.build_matrix(self.roles, self.objects)

    def test_matrix_is_cartesian_product_with_declared_policy(self):
        self.assertEqual(len(self.matrix), 3)
        expected = {row["role"]: row["expected_access"] for row in self.matrix}
        self.assertEqual(expected, {"anonymous": False, "member": True, "manager": True})

    def test_missing_result_is_untested_not_a_negative(self):
        result = matrix_module.evaluate_matrix(self.matrix, [])
        self.assertEqual(result["counts"]["untested"], 3)
        self.assertEqual(result["counts"]["expected_denial"], 0)

    def test_status_only_cross_role_success_is_candidate(self):
        result = matrix_module.evaluate_matrix(self.matrix, [
            {"role": "anonymous", "object_id": "invoice-42", "access": "allowed"}])
        row = next(case for case in result["cases"] if case["role"] == "anonymous")
        self.assertEqual(row["status"], "candidate_violation")

    def test_confirmed_violation_requires_identity_ownership_and_data_proof(self):
        evidence = {"role": "anonymous", "object_id": "invoice-42", "access": "allowed",
                    "role_identity_verified": True, "owner_control_passed": True,
                    "object_identity_verified": True, "unauthorized_data_proof": True}
        result = matrix_module.evaluate_matrix(self.matrix, [evidence])
        row = next(case for case in result["cases"] if case["role"] == "anonymous")
        self.assertEqual(row["status"], "confirmed_violation")
        evidence["unauthorized_data_proof"] = False
        result = matrix_module.evaluate_matrix(self.matrix, [evidence])
        row = next(case for case in result["cases"] if case["role"] == "anonymous")
        self.assertEqual(row["status"], "candidate_violation")

    def test_expected_denial_and_allowed_access_are_not_findings(self):
        results = [
            {"role": "anonymous", "object_id": "invoice-42", "access": "denied"},
            {"role": "member", "object_id": "invoice-42", "access": "allowed"},
        ]
        report = matrix_module.evaluate_matrix(self.matrix, results)
        self.assertEqual(report["counts"]["expected_denial"], 1)
        self.assertEqual(report["counts"]["expected_access"], 1)
        self.assertEqual(report["counts"]["confirmed_violation"], 0)

    def test_policy_and_roles_must_be_explicit_and_consistent(self):
        with self.assertRaisesRegex(matrix_module.RoleMatrixError, "explicit"):
            matrix_module.build_matrix(self.roles, [{"id": "item", "owner_role": "member"}])
        with self.assertRaisesRegex(matrix_module.RoleMatrixError, "owner role"):
            matrix_module.build_matrix(self.roles, [{"id": "item", "owner_role": "member",
                                                    "allowed_roles": ["manager"]}])
        with self.assertRaisesRegex(matrix_module.RoleMatrixError, "declared"):
            matrix_module.build_matrix(self.roles, [{"id": "item", "owner_role": "member",
                                                    "allowed_roles": ["member", "admin"]}])

    def test_duplicate_role_or_object_ids_are_rejected(self):
        with self.assertRaisesRegex(matrix_module.RoleMatrixError, "unique"):
            matrix_module.build_matrix(["member", "member"], [])
        objects = [self.objects[0], dict(self.objects[0])]
        with self.assertRaisesRegex(matrix_module.RoleMatrixError, "unique"):
            matrix_module.build_matrix(self.roles, objects)


if __name__ == "__main__":
    unittest.main()
