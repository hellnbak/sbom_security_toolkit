import json
from argparse import Namespace
from pathlib import Path

from sbomops import connectors
from sbomops.ui import main as ui_main


def test_registry_add_list_and_dry_run(tmp_path):
    registry = tmp_path / 'connectors.yml'
    config = tmp_path / 'snyk.yml'
    config.write_text('org_id: demo\ntoken_ref: env:SNYK_TOKEN\n')
    out = connectors.add_connector(Namespace(registry=str(registry), name='snyk-demo', type='snyk', config=str(config), allow_write=False, insecure_skip_tls_verify=False, timeout_seconds=10, retries=2))
    assert Path(out['path']).exists()
    listed = connectors.list_connectors(Namespace(registry=str(registry)))
    assert listed['count'] == 1
    assert listed['connectors'][0]['read_only'] is True
    result = connectors.execute(Namespace(registry=str(registry), name='snyk-demo', send=False, out=str(tmp_path/'test.json')), 'test')
    assert result['result']['ok'] is True
    assert result['result']['mode'] == 'dry-run'


def test_all_connector_smoke_and_ui(tmp_path, monkeypatch):
    smoke_dir = tmp_path / 'reports' / 'connector-smoke'
    result = connectors.smoke(Namespace(out_dir=str(smoke_dir), sbom='test-sboms/example-spdx-2.3.json', findings=''))
    assert result['ok'] is True
    assert result['checks'] == 10
    monkeypatch.setattr('sys.argv', ['ui', '--reports-dir', str(tmp_path/'reports'), '--out', str(tmp_path/'reports/ui/index.html')])
    ui_main()
    html = (tmp_path/'reports/ui/index.html').read_text()
    assert 'Connector Platform' in html
    assert 'snyk-demo' in html


def test_write_guard_for_dependency_track():
    c = connectors.DependencyTrackConnector('dt', {'read_only': True})
    result = c.sync(send=True, sbom='missing.json')
    assert not result.ok
    assert 'read-only' in result.error


def test_tls_disable_restricted():
    client = connectors.HttpClient(verify_tls=False, retries=1)
    try:
        client.request('https://example.com')
    except ValueError as exc:
        assert 'localhost' in str(exc)
    else:
        raise AssertionError('expected ValueError')
