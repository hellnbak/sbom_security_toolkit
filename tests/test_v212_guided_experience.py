import threading
import urllib.parse
import urllib.request
import unittest
from http.server import ThreadingHTTPServer
from sbomops.workbench import server

class GuidedExperienceTests(unittest.TestCase):
    def test_guided_routes_registered(self):
        source=open(server.__file__,encoding="utf-8").read()
        for route in ["/welcome","/project/new","/connectors/setup","/help","/sample"]:
            self.assertIn(route,source)

    def test_guided_routes_render(self):
        httpd=ThreadingHTTPServer(("127.0.0.1",0),server.Handler)
        thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
        try:
            base=f"http://127.0.0.1:{httpd.server_address[1]}"
            for route in ["/welcome","/welcome?step=2","/welcome?step=3","/welcome?step=4","/welcome?step=5","/project/new","/connectors/setup","/help","/sample"]:
                with urllib.request.urlopen(base+route,timeout=10) as r:
                    self.assertEqual(r.status,200,route)
        finally:
            httpd.shutdown(); thread.join(timeout=5); httpd.server_close()

    def test_safe_connector_defaults(self):
        source=open(server.__file__,encoding="utf-8").read()
        self.assertIn("'dry_run':True",source)
        self.assertIn("'read_only':not self.bool_field",source)

if __name__=="__main__": unittest.main()
