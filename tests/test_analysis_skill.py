"""Run the installed skill without the repository or a capture binary."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from tests.test_network_report import filter_fixture

ROOT = Path(__file__).resolve().parents[1]
SKILL = ROOT/'skills/anettrace-analysis'


class AnalysisSkillTest(unittest.TestCase):
    def test_copied_skill_inspects_generates_and_validates_outside_repository(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            installed = work/'installed skill'
            shutil.copytree(SKILL, installed, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
            trace = work/'capture with spaces.pftrace'
            filter_fixture(trace)
            script = installed/'scripts/network_report.py'
            env = dict(os.environ)
            env.pop('PYTHONPATH', None)
            def run(*args, ok=True):
                result = subprocess.run([sys.executable, str(script), *map(str,args)],
                    cwd=work, env=env, text=True, capture_output=True)
                if ok: self.assertEqual(result.returncode, 0, result.stderr)
                else: self.assertNotEqual(result.returncode, 0)
                return result
            found = json.loads(run('inspect',trace).stdout)
            self.assertEqual({i['value'] for i in found['inventory']['uids']}, {1001,1002})
            out = work/'report'
            run('analyze',trace,'--uid','1002','--min-call-ms','1','--out',out)
            result = json.loads((out/'report.json').read_text())
            self.assertEqual([c['call_id'] for c in result['slow_calls']], ['call-b'])
            self.assertEqual(result['scope']['filters']['uids'], [1002])
            run('validate',out)
            trace.write_bytes(b'changed')
            run('validate',out,ok=False)
            missing = subprocess.run([sys.executable,'-S',str(script),'inspect',str(trace)],
                cwd=work, env=env, text=True, capture_output=True)
            self.assertEqual(missing.returncode, 2)
            self.assertIn(str(installed/'requirements.txt'), missing.stderr)
            self.assertNotIn('tools/requirements-perfetto.txt', missing.stderr)

    def test_legacy_cli_uses_skill_implementation(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            trace = work/'capture.pftrace'
            filter_fixture(trace)
            out = work/'report'
            subprocess.run([sys.executable,str(ROOT/'tools/network_report.py'),'analyze',
                str(trace),'--flow','tcp-1','--out',str(out)],cwd=work,check=True,capture_output=True)
            result = json.loads((out/'report.json').read_text())
            self.assertEqual([c['call_id'] for c in result['slow_calls']], ['call-a'])
