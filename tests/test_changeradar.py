import sys, unittest
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import changeradar as cr

EVENT = {"id": "e1", "title": "t", "category": "c", "source": "https://x.example",
         "effective_at": "2026-10-11", "severity": "high",
         "affected": [{"role": "dnssec-validating-resolver", "condition": "ancre absente",
                       "check": {"fact": "anchor", "equals": False}}]}

def asset(**kw):
    return {"id": "a", "product": "unbound", "role": "dnssec-validating-resolver", **kw}

class Engine(unittest.TestCase):
    def test_unknown_facts_means_verify_not_affected(self):
        self.assertEqual(cr.evaluate(asset(version="version-connue"), EVENT).status, cr.VERIFY)
    def test_fact_confirms(self):
        self.assertEqual(cr.evaluate(asset(facts={"anchor": False}), EVENT).status, cr.AFFECTED)
    def test_fact_denies(self):
        self.assertEqual(cr.evaluate(asset(facts={"anchor": True}), EVENT).status, cr.NOT_AFFECTED)
    def test_no_match(self):
        self.assertIsNone(cr.evaluate({"id": "w", "product": "nginx", "role": "web"}, EVENT))
    def test_versions(self):
        self.assertTrue(cr.version_in_range("1.18.9", "<1.19"))
        self.assertFalse(cr.version_in_range("1.19", "<1.19"))
        self.assertIsNone(cr.version_in_range("version-connue", "<1.19"))
    def test_version_unknown_blocks_certainty(self):
        ev = {**EVENT, "affected": [{"product": "unbound", "versions": "<1.19"}]}
        self.assertEqual(cr.evaluate(asset(version="inconnue"), ev).status, cr.VERIFY)
    def test_validation(self):
        errs, _ = cr.validate_event({**EVENT, "severity": "nope", "source": "http://x"})
        self.assertEqual(len(errs), 2)

if __name__ == "__main__":
    unittest.main()
