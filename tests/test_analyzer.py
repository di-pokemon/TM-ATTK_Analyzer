import unittest

from analyzer.attack_graph import build_attack_paths
from analyzer.risk_scorer import calculate_risk
from analyzer.stride_engine import generate_stride_threats


class AnalyzerTests(unittest.TestCase):
    def test_generate_stride_threats_includes_six_categories(self):
        system = {"system": "Sample App"}
        threats = generate_stride_threats(system)

        categories = [threat["category"] for threat in threats]
        self.assertEqual(len(threats), 6)
        self.assertIn("Spoofing", categories)
        self.assertIn("Tampering", categories)
        self.assertIn("Repudiation", categories)
        self.assertIn("Information Disclosure", categories)
        self.assertIn("Denial of Service", categories)
        self.assertIn("Elevation of Privilege", categories)
        self.assertIn("Sample App", threats[0]["description"])

    def test_build_attack_paths_conditional_database_path(self):
        with_database = {"components": ["Frontend", "Database"]}
        without_database = {"components": ["Frontend", "Backend API"]}

        paths_with_db = build_attack_paths(with_database)
        paths_without_db = build_attack_paths(without_database)

        db_attack_path = "User -> API -> Injection -> Database Leak"
        self.assertIn(db_attack_path, [path["attack_path"] for path in paths_with_db])
        self.assertNotIn(db_attack_path, [path["attack_path"] for path in paths_without_db])

    def test_calculate_risk_returns_expected_score_and_level(self):
        threats = [
            {"category": "Spoofing"},
            {"category": "Tampering"},
            {"category": "Repudiation"},
        ]
        paths = [
            {"risk": "HIGH"},
            {"risk": "HIGH"},
            {"risk": "MEDIUM"},
        ]

        risk = calculate_risk(threats, paths)

        self.assertEqual(risk["risk_score"], 57)
        self.assertEqual(risk["risk_level"], "HIGH")


if __name__ == "__main__":
    unittest.main()
