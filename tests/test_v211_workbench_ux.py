import unittest
from sbomops.workbench import server


class WorkbenchUXTests(unittest.TestCase):
    def test_primary_routes_are_registered(self):
        source = open(server.__file__, encoding="utf-8").read()
        for route in ["/dashboard", "/decisions", "/actions", "/exceptions", "/evidence", "/search"]:
            self.assertTrue(route in source or hasattr(server.Handler, route.strip("/").replace("-", "_") + "_page"))

    def test_navigation_contains_workflow_sections(self):
        labels = [label for _, links in server.NAV for _, label in links]
        for label in ["Overview", "Projects", "Scans", "Findings", "Release Decisions", "Action Center", "Exceptions", "Connectors", "Reports", "Evidence"]:
            self.assertIn(label, labels)

    def test_responsive_shell_is_present(self):
        self.assertIn("@media(max-width:900px)", server.CSS)
        self.assertIn("grid-template-columns:250px 1fr", server.CSS)

    def test_version(self):
        from sbomops.__version__ import __version__
        self.assertEqual(__version__, "2.14.2")


if __name__ == "__main__":
    unittest.main()
