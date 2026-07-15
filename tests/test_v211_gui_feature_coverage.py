import threading
import urllib.request
import unittest
from http.server import ThreadingHTTPServer

from sbomops.workbench import server


class GUIFeatureCoverageTests(unittest.TestCase):
    def test_security_controls_are_in_navigation(self):
        labels = [label for _, links in server.NAV for _, label in links]
        self.assertIn("Security Controls", labels)

    def test_backend_capabilities_have_gui_labels(self):
        source = open(server.__file__, encoding="utf-8").read() + open(server.experience_runtime.__file__, encoding="utf-8").read() if hasattr(server, "experience_runtime") else open(server.__file__, encoding="utf-8").read()
        for label in ["Release Assurance", "VEX", "Provenance", "Evidence", "Organization Context", "Remediation"]:
            self.assertIn(label, source)

    def test_primary_routes_render(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            routes = ["/dashboard", "/projects", "/jobs", "/findings", "/decisions", "/actions", "/controls", "/exceptions", "/integrations", "/reports", "/evidence", "/settings", "/admin", "/repository", "/fuzzing", "/scanners", "/demo"]
            for route in routes:
                with urllib.request.urlopen(base + route, timeout=10) as response:
                    self.assertEqual(response.status, 200, route)
                    self.assertIn(b"SBOM Security Toolkit", response.read(), route)
        finally:
            httpd.shutdown(); thread.join(timeout=5); httpd.server_close()


if __name__ == "__main__":
    unittest.main()
