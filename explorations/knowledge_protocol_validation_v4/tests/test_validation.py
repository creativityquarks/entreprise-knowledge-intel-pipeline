import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from validate import affected, run, ROOT

class ProtocolTests(unittest.TestCase):
    def test_known_versions(self):
        cases=[('2.14.1','affected'),('2.15.0','not_affected'),('2.17.1','not_affected'),('2.0.0','unknown'),('2.14.1-SNAPSHOT','unknown')]
        for version,expected in cases:
            with self.subTest(version=version):
                self.assertEqual(affected(version,'2.0-beta9','2.15.0'),expected)
    def test_two_runs_and_evidence(self):
        r=run()
        self.assertEqual(r['graph_run1']['edges'],3)
        self.assertEqual(r['graph_run2']['edges'],2)
        self.assertEqual(r['foreign_key_violations'],[])
        self.assertEqual(r['snapshots'],5)

if __name__=='__main__':
    unittest.main()
