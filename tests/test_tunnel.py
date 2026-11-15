import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import unittest
import uuid

import homologation
from test_poc import TempDirectory


@unittest.skipUnless(shutil.which('powershell'), 'Windows PowerShell unavailable')
class TunnelCommands(unittest.TestCase):
    script = Path(__file__).resolve().parents[1] / 'Tunnel.ps1'

    def invoke(self, runtime, command, *args):
        return subprocess.run(['powershell', '-NoProfile', '-File', str(self.script), command,
            '-RuntimeDirectory', str(runtime), *args], capture_output=True, text=True, timeout=15)

    def logs(self, root):
        runtime = root / 'runtime'
        runtime.mkdir()
        name = 'agent-' + uuid.uuid4().hex
        out, err = runtime / (name + '.log'), runtime / (name + '.stderr.log')
        out.write_text('stdout-old\nstdout-last1\nstdout-last2\n', encoding='utf-8')
        err.write_text('stderr-old\nstderr-last1\nstderr-last2\n', encoding='utf-8')
        (runtime / 'last-run.json').write_text(json.dumps({'stdout': str(out), 'stderr': str(err)}))
        return runtime, out, err

    def test_logs_tail_both_streams_after_agent_stopped(self):
        with TempDirectory() as directory:
            runtime, out, err = self.logs(Path(directory))
            result = self.invoke(runtime, 'logs', '-Tail', '2')
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('stdout-last1', result.stdout)
            self.assertIn('stderr-last2', result.stdout)
            self.assertNotIn('stdout-old', result.stdout)
            self.assertNotIn('stderr-old', result.stdout)

    def test_logs_tail_large_utf8_file(self):
        with TempDirectory() as directory:
            runtime, out, err = self.logs(Path(directory))
            with out.open('w', encoding='utf-8') as stream:
                for index in range(20000):
                    stream.write('linha-' + str(index) + '-acao-\u00e7\u00e3o\n')
            result = self.invoke(runtime, 'logs', '-Tail', '2')
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            self.assertIn('linha-19998-', result.stdout)
            self.assertIn('linha-19999-', result.stdout)
            self.assertNotIn('linha-19997-', result.stdout)

    def test_logs_follow_observes_stdout_and_stderr(self):
        with TempDirectory() as directory:
            root = Path(directory)
            runtime, out, err = self.logs(root)
            capture, errors = root / 'follow.out', root / 'follow.err'
            with capture.open('w') as output, errors.open('w') as stderr:
                process = subprocess.Popen(['powershell', '-NoProfile', '-File', str(self.script),
                    'logs', '-RuntimeDirectory', str(runtime), '-Tail', '1', '-Follow'], stdout=output, stderr=stderr)
                try:
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline and 'stdout-last2' not in capture.read_text(errors='replace'):
                        self.assertIsNone(process.poll(), errors.read_text(errors='replace'))
                        time.sleep(.1)
                    with out.open('a') as stream:
                        stream.write('stdout-new\n')
                    with err.open('a') as stream:
                        stream.write('stderr-new\n')
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        text = capture.read_text(errors='replace')
                        if 'stdout-new' in text and 'stderr-new' in text:
                            break
                        time.sleep(.1)
                    self.assertIn('stdout-new', text)
                    self.assertIn('stderr-new', text)
                finally:
                    process.terminate()
                    process.wait(10)

    def test_logs_refuse_paths_outside_runtime(self):
        with TempDirectory() as directory:
            root = Path(directory)
            runtime, out, err = self.logs(root)
            private = root / 'private.token'
            private.write_text('synthetic-private-content')
            (runtime / 'last-run.json').write_text(json.dumps({'stdout': str(private), 'stderr': str(err)}))
            result = self.invoke(runtime, 'logs')
            self.assertNotEqual(0, result.returncode)
            self.assertNotIn('synthetic-private-content', result.stdout + result.stderr)

    def test_raw_json_parameter_applies_policy_without_importing_client_token(self):
        with TempDirectory() as directory:
            root = Path(directory)
            homologation.prepare(root / 'policies', hours=720)
            policy = json.loads((root / 'policies/agent-policy.json').read_text())
            config = root / 'agent.json'
            config.write_text(json.dumps({'agent_id':'windows-lab-01','agent_url':'https://unused.invalid',
                'tls_ca':'missing.crt','signing_key':'missing.key','gateway_public':'missing.pub'}))
            result = self.invoke(root / 'runtime', 'rotate-client-token', '-Config', str(config),
                                 '-PolicyJson', json.dumps(policy))
            # Policy is applied, but absent private files must prevent startup.
            self.assertNotEqual(0, result.returncode)
            applied = json.loads(config.read_text(encoding='utf-8-sig'))
            self.assertEqual(policy['patch']['services'], applied['services'])
            self.assertNotIn('client_token', applied)
            self.assertFalse((root / 'runtime/agent.json').exists())
            self.assertFalse(list((root / 'runtime').glob('policy-*.json')))
            result = subprocess.run(['cmd.exe', '/d', '/c', str(self.script.with_name('tunnel.cmd')),
                'rotate-client-token', '-RuntimeDirectory', str(root / 'runtime'), '-Config', str(config),
                '-PolicyStdin'], input=json.dumps(policy), capture_output=True, text=True, timeout=15)
            self.assertNotEqual(0, result.returncode)
            self.assertIn('validated only', result.stdout, result.stdout + result.stderr)
            self.assertFalse((root / 'runtime/agent.json').exists())


    def test_missing_status_down_and_failed_up_are_safe(self):
        with TempDirectory() as directory:
            root = Path(directory)
            runtime = root / 'runtime'
            for command in ('status', 'down'):
                result = self.invoke(runtime, command)
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertIn('agent_not_running', result.stdout)
            result = self.invoke(runtime, 'up', '-Config', str(root / 'missing.json'))
            self.assertNotEqual(0, result.returncode)
            self.assertFalse((runtime / 'agent.json').exists())
