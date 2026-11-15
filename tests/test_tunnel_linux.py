import os
from pathlib import Path
import shutil
import subprocess
import unittest

from test_poc import TempDirectory


class LinuxTunnelCommands(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        git_bash = Path('C:/Program Files/Git/bin/bash.exe')
        cls.bash = str(git_bash) if os.name == 'nt' and git_bash.exists() else shutil.which('bash')
        if not cls.bash:
            raise unittest.SkipTest('Bash unavailable')
        root = Path(__file__).resolve().parents[1]
        cls.script = subprocess.check_output([cls.bash, '-c', 'pwd -P'], cwd=root, text=True).strip() + '/tunnel.sh'

    def run_commands(self, commands):
        with TempDirectory() as directory:
            root = Path(directory)
            binary = root / 'bin'
            binary.mkdir()
            unix = subprocess.check_output([self.bash, '-c', 'pwd -P'], cwd=root, text=True).strip()
            scripts = {
                'sudo': '#!/usr/bin/env bash\nexec "$@"\n',
                'systemctl': '#!/usr/bin/env bash\nprintf "systemctl %s\\n" "$*" >> "$TUNNEL_TEST_OUTPUT"\n',
                'journalctl': '#!/usr/bin/env bash\nprintf "journalctl %s\\n" "$*" >> "$TUNNEL_TEST_OUTPUT"\necho synthetic-service-log\n',
                'python3': '#!/usr/bin/env bash\nprintf "python3 %s\\n" "$*" >> "$TUNNEL_TEST_OUTPUT"\nif [[ "$1" == "-" ]]; then cat >/dev/null; echo synthetic-token-display; else echo "{}"; fi\n',
            }
            for name, text in scripts.items():
                path = binary / name
                path.write_text(text, encoding='utf-8', newline='\n')
                path.chmod(0o755)
            env = dict(os.environ, TUNNEL_TEST_BIN=unix + '/bin', TUNNEL_TEST_OUTPUT=unix + '/calls',
                       TUNNEL_SCRIPT=self.script)
            results = []
            for command in commands:
                results.append(subprocess.run([self.bash, '-c',
                    'export PATH="$TUNNEL_TEST_BIN:$PATH"; exec bash "$TUNNEL_SCRIPT" "$@"', '_', *command],
                    env=env, cwd=root, capture_output=True, text=True, timeout=15))
            calls = (root / 'calls').read_text() if (root / 'calls').exists() else ''
            return results, calls

    def test_service_controls_and_logs_use_only_expected_units(self):
        results, calls = self.run_commands([['up'], ['down'], ['status'], ['check'],
                                            ['logs', '--tail', '12', '--follow'], ['restart']])
        for result in results:
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn('systemctl start haproxy gateway-poc-https', calls)
        self.assertIn('systemctl stop gateway-poc-https', calls)
        self.assertNotIn('systemctl stop haproxy', calls)
        self.assertIn('journalctl -u gateway-poc-https -n 12 --no-pager -f', calls)
        self.assertIn('check-gateway --config /etc/gateway-poc-https/config.json', calls)

    def test_rotation_and_invalid_arguments(self):
        results, calls = self.run_commands([['rotate-client-token', '--client-id', 'intermediario-01',
                                            '--hours', '720', '--out', '/private/rotation']])
        self.assertEqual(0, results[0].returncode, results[0].stdout + results[0].stderr)
        self.assertIn('rotate-client-token --config /etc/gateway-poc-https/config.json --out /private/rotation --client-id intermediario-01 --hours 720', calls)
        self.assertIn('systemctl restart gateway-poc-https', calls)
        self.assertIn('synthetic-token-display', results[0].stdout)
        results, calls = self.run_commands([['rotate-client-token', '--hours', '721'], ['logs', '--tail', '0'],
                                            ['up', '--out', '/not-allowed']])
        self.assertTrue(all(result.returncode == 2 for result in results))
        self.assertEqual('', calls)
