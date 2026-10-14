import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app import app, interpret_detection


class DashboardTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_routes(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        for asset in ('app.js', 'core.js', 'style.css', 'world.json'):
            with self.client.get('/static/' + asset) as response:
                self.assertEqual(response.status_code, 200, asset)

    def test_healthz(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as tmp, patch.dict(app.config, GEODB_PATH='/not/a/database.mmdb', DB_PATH=os.path.join(tmp, 'h.db')):
            data = self.client.get('/healthz').get_json()
        self.assertTrue(data['database']['ok'])
        self.assertEqual(data['status'], 'ok')
        self.assertFalse(data['geodb']['configured'])

    def test_public_ip_and_hash_links(self):
        data = self.client.post('/summary', json={'ip': '8.8.8.8', 'hash': 'a' * 64, 'threat': 'HTML/Phishing.Agent'}).get_json()
        self.assertEqual(data['scope'], 'Public IP')
        self.assertTrue(data['hash_valid'])
        self.assertEqual(len(data['links']), 4)
        self.assertIn('phishing', data['explanation'])
        self.assertEqual(data['category'], 'Phishing')
        self.assertEqual(data['platform'], 'HTML page or attachment')

    def test_internal_and_invalid_indicators(self):
        for ip in ['10.0.0.1', '::1', 'fd00::1', '192.0.2.1', 'not an ip', 'https://evil.example']:
            data = self.client.post('/summary', json={'ip': ip, 'hash': 'not a hash'}).get_json()
            self.assertFalse(data['hash_valid'])
            self.assertEqual(len(data['links']), 0)

    def test_cve_link(self):
        data = self.client.post('/summary', json={'threat': 'Win32/Exploit.CVE-2017-11882.A trojan'}).get_json()
        self.assertEqual(data['cves'], ['CVE-2017-11882'])
        self.assertEqual(data['category'], 'Exploit')
        self.assertTrue(any(l['url'] == 'https://nvd.nist.gov/vuln/detail/CVE-2017-11882' for l in data['links']))

    def test_validation_and_headers(self):
        self.assertEqual(self.client.post('/summary', json=[]).status_code, 400)
        response = self.client.get('/')
        self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])


class InterpretationTests(unittest.TestCase):
    def test_eset_names(self):
        cases = {
            'MSIL/Spy.AgentTesla.F trojan': ('.NET (MSIL) program', 'AgentTesla', 'F', 'Spyware / information stealer'),
            'Win32/Filecoder.Phobos.C trojan': ('32-bit Windows program', 'Phobos', 'C', 'Ransomware'),
            'Win64/CoinMiner.KV potentially unwanted application': ('64-bit Windows program', None, 'KV', 'Cryptocurrency miner'),
            'VBA/TrojanDownloader.Agent.ZXK trojan': ('Office document macro (VBA)', None, 'ZXK', 'Downloader / dropper'),
            'Win32/InstallCore.D potentially unwanted application': ('32-bit Windows program', 'InstallCore', 'D', 'Potentially unwanted application'),
        }
        for name, (platform, family, variant, category) in cases.items():
            info = interpret_detection(name)
            self.assertEqual((info['platform'], info['family'], info['variant'], info['category']), (platform, family, variant, category), name)

    def test_network_names(self):
        self.assertEqual(interpret_detection('RDP.Attack.Bruteforce')['category'], 'Brute-force attack')
        self.assertEqual(interpret_detection('Botnet.CnC.Generic')['category'], 'Botnet communication')
        self.assertEqual(interpret_detection('Incoming.Attack.Generic')['category'], 'Network attack')
        self.assertIsNone(interpret_detection('Incoming.Attack.Generic')['platform'])
        self.assertIsNone(interpret_detection('Something odd')['category'])


class GeoDBTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_private_and_invalid_without_database(self):
        result = self.client.post('/geolocate', json={'ips': ['10.16.8.3', '::1', 'bad']}).get_json()['results']
        self.assertEqual(result['10.16.8.3']['status'], 'internal')
        self.assertEqual(result['::1']['status'], 'internal')
        self.assertEqual(result['bad']['status'], 'invalid')

    def test_missing_database_and_validation(self):
        with patch.dict(app.config, GEODB_PATH='/not/a/database.mmdb'):
            response = self.client.post('/geolocate', json={'ips': ['8.8.8.8', '10.16.8.3']})
            self.assertEqual(response.status_code, 503)
            self.assertEqual(response.get_json()['results']['10.16.8.3']['status'], 'internal')
        self.assertEqual(self.client.post('/geolocate', json={'ips': [{}]}).status_code, 400)
        self.assertEqual(self.client.post('/geolocate', json={'ips': ['8.8.8.8'] * 501}).status_code, 400)

    def test_city_database_lookup(self):
        reader = MagicMock()
        reader.metadata.return_value.database_type = 'GeoLite2-City'
        reader.city.return_value = SimpleNamespace(country=SimpleNamespace(name='Czechia', iso_code='CZ'), city=SimpleNamespace(name='Prague'),
                                                   location=SimpleNamespace(latitude=50.1, longitude=14.4, accuracy_radius=20))
        with patch('pathlib.Path.is_file', return_value=True), patch('geoip2.database.Reader', return_value=reader):
            response = self.client.post('/geolocate', json={'ips': ['8.8.8.8', '10.16.8.3']})
            self.assertEqual(response.status_code, 200)
            result = response.get_json()['results']['8.8.8.8']
            self.assertEqual(result['country_code'], 'CZ')
            self.assertEqual(result['city'], 'Prague')
            reader.city.assert_called_once_with('8.8.8.8')


if __name__ == '__main__':
    unittest.main()
