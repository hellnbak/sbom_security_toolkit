import threading
import urllib.request
import unittest
from http.server import ThreadingHTTPServer
from sbomops.workbench import server


class GuidedExperienceTests(unittest.TestCase):
    def test_guided_routes_registered(self):
        for method in ["welcome_page", "project_wizard", "connectors_setup", "help_page", "sample_page"]:
            self.assertTrue(hasattr(server.Handler, method))

    def test_guided_routes_render(self):
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{httpd.server_address[1]}"
            for route in ["/welcome", "/welcome?step=2", "/welcome?step=3", "/welcome?step=4", "/welcome?step=5", "/project/new", "/connectors/setup", "/help", "/sample"]:
                with urllib.request.urlopen(base + route, timeout=10) as response:
                    self.assertEqual(response.status, 200, route)
        finally:
            httpd.shutdown(); thread.join(timeout=5); httpd.server_close()

    def test_safe_connector_defaults(self):
        source = open(server.Handler.connectors_setup_save.__code__.co_filename, encoding="utf-8").read()
        self.assertIn("read-only", source)
        self.assertIn("dry-run", source)


if __name__ == "__main__":
    unittest.main()
