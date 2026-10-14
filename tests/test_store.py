import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from app import app


def row(**kw):
    base = {'t': 1760000000000, 'threat': 'JS/Agent.QQV trojan', 'computer': 'PC-1', 'user': 'DOMAIN\\alice', 'ip': '8.8.8.8',
            'severity': 'High', 'action': 'Blocked', 'resolved': 'No', 'occurrences': 1, 'raw': {'Occurred [column 1]': '14.10.2026'}}
    base.update(kw)
    return base


class StoreAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cfg = patch.dict(app.config, DB_PATH=os.path.join(self.tmp.name, 'test.db'), GEODB_PATH='/not/a/database.mmdb')
        self.cfg.start()
        self.client = app.test_client()

    def tearDown(self):
        self.cfg.stop()
        self.tmp.cleanup()

    def import_rows(self, rows, name='export.csv'):
        import_id = self.client.post('/api/imports', json={'name': name}).get_json()['id']
        return import_id, self.client.post(f'/api/imports/{import_id}/rows', json={'rows': rows}).get_json()

    def test_import_and_deduplicate(self):
        _, first = self.import_rows([row(), row(t=1760000001000), row(t=None, date_raw='garbage')])
        self.assertEqual((first['new'], first['duplicate']), (3, 0))
        _, second = self.import_rows([row(), row(t=1760000001000, occurrences=4, resolved='Yes'), row(t=1760000002000)])
        self.assertEqual((second['new'], second['updated'], second['duplicate']), (1, 1, 1))
        data = self.client.get('/api/detections').get_json()
        self.assertEqual(data['stats']['detections'], 4)
        self.assertEqual(data['stats']['imports'], 2)
        cols = data['columns']
        updated = next(r for r in data['rows'] if r[cols.index('t')] == 1760000001000)
        self.assertEqual(updated[cols.index('occurrences')], 4)
        self.assertEqual(updated[cols.index('resolved')], 'Yes')
        self.assertEqual(updated[cols.index('status')], 'new')

    def test_status_notes_and_history(self):
        self.import_rows([row()])
        det_id = self.client.get('/api/detections').get_json()['rows'][0][0]
        detail = self.client.patch(f'/api/detections/{det_id}', json={'status': 'investigating', 'note': 'Called Alice'}).get_json()
        self.assertEqual(detail['status'], 'investigating')
        self.assertEqual(detail['note'], 'Called Alice')
        self.assertEqual({h['field'] for h in detail['history']}, {'status', 'note'})
        self.assertEqual(detail['raw'], {'Occurred [column 1]': '14.10.2026'})
        # Status and notes survive a re-import of the same event.
        self.import_rows([row()])
        again = self.client.get(f'/api/detections/{det_id}').get_json()
        self.assertEqual((again['status'], again['note'], len(again['imports'])), ('investigating', 'Called Alice', 2))
        self.assertEqual(self.client.patch(f'/api/detections/{det_id}', json={'status': 'bogus'}).status_code, 400)
        self.assertEqual(self.client.patch('/api/detections/9999', json={'status': 'closed'}).status_code, 404)

    def test_bulk_status(self):
        self.import_rows([row(t=1760000000000 + i) for i in range(5)])
        ids = [r[0] for r in self.client.get('/api/detections').get_json()['rows']]
        self.assertEqual(self.client.post('/api/detections/status', json={'ids': ids[:3], 'status': 'closed'}).get_json()['changed'], 3)
        self.assertEqual(self.client.post('/api/detections/status', json={'ids': ids, 'status': 'closed'}).get_json()['changed'], 2)
        self.assertEqual(self.client.post('/api/detections/status', json={'ids': ['x'], 'status': 'closed'}).status_code, 400)

    def test_delete_import_keeps_shared_rows(self):
        first, _ = self.import_rows([row(), row(t=1)])
        second, _ = self.import_rows([row(), row(t=2)])
        self.assertEqual(self.client.delete(f'/api/imports/{second}').get_json()['removed'], 1)
        self.assertEqual(self.client.get('/api/detections').get_json()['stats']['detections'], 2)
        self.assertEqual(self.client.delete(f'/api/imports/{first}').get_json()['removed'], 2)
        self.assertEqual(self.client.delete('/api/imports/999').status_code, 404)

    def test_purge_and_backup(self):
        self.import_rows([row(t=1000), row(t=None, date_raw='x'), row(t=4102444800000)])
        self.assertEqual(self.client.post('/api/purge', json={'older_than_days': 30}).get_json()['removed'], 1)
        self.assertEqual(self.client.post('/api/purge', json={'older_than_days': 0}).status_code, 400)
        backup = self.client.get('/api/backup')
        self.assertEqual(backup.status_code, 200)
        path = os.path.join(self.tmp.name, 'restored.db')
        with open(path, 'wb') as fh:
            fh.write(backup.data)
        with sqlite3.connect(path) as conn:
            self.assertEqual(conn.execute('SELECT COUNT(*) FROM detections').fetchone()[0], 2)
        backup.close()
        self.assertEqual(self.client.post('/api/purge', json={'everything': True}).get_json()['removed'], 2)
        self.assertEqual(self.client.get('/api/imports').get_json()['imports'], [])

    def test_validation_and_cross_site_protection(self):
        import_id = self.client.post('/api/imports', json={'name': 'x'}).get_json()['id']
        self.assertEqual(self.client.post(f'/api/imports/{import_id}/rows', json={'rows': []}).status_code, 400)
        self.assertEqual(self.client.post(f'/api/imports/{import_id}/rows', json={'rows': ['nope']}).status_code, 400)
        self.assertEqual(self.client.post('/api/imports/999/rows', json={'rows': [row()]}).status_code, 404)
        self.assertEqual(self.client.post('/api/imports', data='name=x', content_type='application/x-www-form-urlencoded').status_code, 415)
        self.assertEqual(self.client.post('/api/imports', json={'name': 'x'}, headers={'Origin': 'https://evil.example'}).status_code, 403)
        self.assertEqual(self.client.post('/api/imports', json={'name': 'x'}, headers={'Origin': 'http://localhost'}).status_code, 201)
        # Odd values are clamped rather than trusted.
        _, res = self.import_rows([row(severity='Apocalyptic', occurrences=-5, t='yesterday', threat='x' * 5000)])
        self.assertEqual(res['new'], 1)
        data = self.client.get('/api/detections').get_json()
        r = dict(zip(data['columns'], data['rows'][0]))
        self.assertEqual((r['severity'], r['occurrences'], r['t'], len(r['threat'])), ('Unknown', 1, None, 512))

    def test_healthz_reports_database(self):
        self.import_rows([row()])
        self.assertEqual(self.client.get('/healthz').get_json()['database']['detections'], 1)


if __name__ == '__main__':
    unittest.main()
