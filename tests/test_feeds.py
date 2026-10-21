import sys, tempfile, unittest
from datetime import date
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import changeradar as cr, feeds

T = date(2026, 10, 21)
DEB = {"label": "Debian", "releases": [
    {"name": "12", "eolFrom": None, "isEol": False, "isMaintained": True},
    {"name": "10", "eolFrom": "2024-06-30", "isEol": True, "isMaintained": False},
    {"name": "9.18", "eolFrom": "2027-12-31", "isEol": False, "isMaintained": True}]}
RSS = (b"<rss><channel><item><title>F5 - CVE-2026-15176</title>"
       b"<link>https://cyberveille.esante.gouv.fr/alertes/f5</link>"
       b"<description>&lt;p&gt;module de &lt;strong&gt;NGINX Plus&lt;/strong&gt; et NGINX Open Source&lt;/p&gt;</description>"
       b"<pubDate>Thu, 15 Oct 2026 01:03:55 +0000</pubDate></item></channel></rss>")

class Eol(unittest.TestCase):
    def test_prefix_match(self):
        self.assertEqual(feeds.match_release("9.18.24", DEB["releases"])["name"], "9.18")
        self.assertIsNone(feeds.match_release("version-connue", DEB["releases"]))
    def test_past_eol_affected(self):
        f = feeds.eol_findings({"id": "a", "version": "10.13"}, "debian", DEB, T)
        self.assertEqual(f["status"], cr.AFFECTED); self.assertIn("12", f["actions"][0])
    def test_supported(self):
        self.assertEqual(feeds.eol_findings({"id": "a", "version": "12.5"}, "debian", DEB, T)["status"], cr.NOT_AFFECTED)
    def test_unknown_version_to_verify(self):
        self.assertEqual(feeds.eol_findings({"id": "a", "version": "?"}, "debian", DEB, T)["status"], cr.VERIFY)

class Cert(unittest.TestCase):
    def setUp(self):
        self.d = Path(tempfile.mkdtemp())
        (self.d / "cert.json").write_text(__import__("json").dumps(feeds.parse_cert(RSS)))
    def test_parse(self):
        it = feeds.parse_cert(RSS)[0]
        self.assertEqual((it["cve"], it["date"]), ("CVE-2026-15176", "2026-10-15")); self.assertIn("NGINX Plus", it["text"])
    def test_name_match_is_only_verify(self):
        f = feeds.findings([{"id": "w", "product": "nginx", "version": "1.25"}], self.d, T)
        self.assertEqual((len(f), f[0]["status"]), (1, cr.VERIFY)); self.assertTrue(f[0]["ask"])
    def test_answer_resolves(self):
        key = feeds.fact_key(feeds.parse_cert(RSS)[0])
        for val, st in ((True, cr.AFFECTED), (False, cr.NOT_AFFECTED)):
            f = feeds.findings([{"id": "w", "product": "nginx", "facts": {key: val}}], self.d, T)
            self.assertEqual(f[0]["status"], st)
    def test_no_false_positive_and_age(self):
        self.assertEqual(feeds.findings([{"id": "u", "product": "unbound"}], self.d, T), [])
        self.assertEqual(feeds.findings([{"id": "w", "product": "nginx"}], self.d, date(2027, 3, 1)), [])

class Terms(unittest.TestCase):
    def test_all_words_required(self):
        hay = cr.norm("Fortinet - CVE-1 interface de FortiGate")
        self.assertTrue(feeds.term_hit("Fortinet FortiGate", hay)); self.assertFalse(feeds.term_hit("Fortinet FortiMail", hay))
        self.assertFalse(feeds.term_hit("nginx", cr.norm("nginxfoo")))
    def test_keywords_and_scope(self):
        d = Path(tempfile.mkdtemp()); (d / "cert.json").write_text(__import__("json").dumps(feeds.parse_cert(RSS)))
        f = feeds.findings([{"id": "F5 BIG-IP", "product": "F5 BIG-IP", "keywords": ["NGINX Plus"], "scope": "tech", "ref": "F5 BIG-IP"}], d, T)
        self.assertEqual((f[0]["scope"], f[0]["ref"], f[0]["status"]), ("tech", "F5 BIG-IP", cr.VERIFY))

if __name__ == "__main__":
    unittest.main()
