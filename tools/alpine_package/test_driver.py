import base64
import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('package_driver', Path(__file__).with_name('driver.py'))
driver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(driver)
A = b'ONYX_DIAG service initial start 0 0 0 0 started absent other'
B = b'ONYX_DIAG service initial status 64 0 0 0 unknown absent other'
C = b'ONYX_DIAG custody initial start absent valid valid'
D = b'ONYX_DIAG custody initial status present valid valid'

class DiagnosticTests(unittest.TestCase):
    def parse(self, data):
        return driver.parse_diagnostics(data, b'ONYX_DIAG service', driver.SERVICE_DIAG)
    def test_adjacent(self):
        self.assertEqual([r['operation'] for r in self.parse(A + b'\n' + B + b'\n')], ['start', 'status'])
    def test_duplicate(self):
        with self.assertRaises(RuntimeError): self.parse(A + b'\n' + A + b'\n')
    def test_malformed(self):
        with self.assertRaises(RuntimeError): self.parse(A + b' extra\n')
        with self.assertRaises(RuntimeError): self.parse(A.replace(b' 0 0 0 0 ', b' 999 0 0 0 ') + b'\n')
    def test_correspondence(self):
        rows = self.parse(A + b'\n' + B + b'\n')
        custody = driver.parse_diagnostics(C + b'\n' + D + b'\n', b'ONYX_DIAG custody', driver.CUSTODY_DIAG)
        captures = {('initial','start'): {}, ('initial','status'): {}}
        driver.validate_correspondence(rows, custody, captures)
        with self.assertRaises(RuntimeError): driver.validate_correspondence(rows, custody[:1], captures)
        with self.assertRaises(RuntimeError): driver.validate_correspondence(rows, custody, {})
        rows[0]['log_reason'] = 'truncated'
        with self.assertRaises(RuntimeError): driver.validate_correspondence(rows, custody, captures)
    def test_capture_duplicate_and_invalid(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as tmp:
            captures = {}; frame = b'ONYX_PRIVATE_SERVICE initial start ' + base64.b64encode(b'private')
            driver.capture_service(frame, Path(tmp), captures)
            self.assertEqual((Path(tmp) / 'initial.start.log').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(RuntimeError): driver.capture_service(frame, Path(tmp), captures)
            with self.assertRaises(RuntimeError): driver.capture_service(b'ONYX_PRIVATE_SERVICE initial status AA=A', Path(tmp), captures)
            identity = b'ONYX_PRIVATE_SERVICE identity probe ' + base64.b64encode(b'private identity log')
            driver.capture_service(identity, Path(tmp), captures)
            self.assertEqual((Path(tmp) / 'identity.probe.log').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(RuntimeError): driver.capture_service(identity, Path(tmp), captures)
            with self.assertRaises(RuntimeError): driver.capture_service(b'ONYX_PRIVATE_SERVICE identity start cA==', Path(tmp), captures)

class ProfileTests(unittest.TestCase):
    def test_bounded_private_profile_capture(self):
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as tmp:
            captures = {}; line = b'ONYX_PRIVATE_PROFILE env ' + base64.b64encode(b'private transcript')
            driver.capture_profile(line, Path(tmp), captures)
            self.assertEqual((Path(tmp) / 'profile-env.log').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(RuntimeError): driver.capture_profile(line, Path(tmp), captures)
            with self.assertRaises(RuntimeError): driver.capture_profile(b'ONYX_PRIVATE_PROFILE unknown cA==', Path(tmp), captures)
    def test_native_observation_exact_matrix_and_carry(self):
        modes = ('file','inline','env','ref')
        lines = [f'ONYX_HELIX {mode} 123 456 789 790 1:999 strict {int(mode == "env")} same'.encode() for mode in modes]
        self.assertEqual(len(driver.parse_helix_observations(b'\n'.join(lines))), 4)
        with self.assertRaises(RuntimeError): driver.parse_helix_observations(b'\n'.join(lines[:-1]))
        with self.assertRaises(RuntimeError): driver.parse_helix_observations(b'\n'.join(lines + [lines[0]]))
        with self.assertRaises(RuntimeError): driver.parse_helix_observations(b'\n'.join(lines).replace(b'env 123 456 789 790 1:999 strict 1', b'env 123 456 789 790 1:999 strict 0'))
    def test_profile_completion_requires_three_real_refusal_classes(self):
        modes = ('file','inline','env','ref')
        rows = [f'ONYX_PROFILE {mode} strict socket exe carry pass'.encode() for mode in modes]
        refusals = [f'ONYX_REFUSAL {kind} {error} retained socket pong'.encode() for kind, error in (('key','ChangedNodeIdentity'),('realm','ChangedNodeRealm'),('env','ChangedBootEnvironment'))]
        driver.profiles_complete(b'\n'.join(rows + refusals), dict.fromkeys(modes))
        with self.assertRaises(RuntimeError): driver.profiles_complete(b'\n'.join(rows + refusals[:-1]), dict.fromkeys(modes))
        with self.assertRaises(RuntimeError): driver.profiles_complete(b'\n'.join(rows + refusals), dict.fromkeys(modes[:-1]))

class StrictEvidenceTests(unittest.TestCase):
    def test_positive_exact_existing_keyfile_evidence_required(self):
        banner = driver.STRICT_IDENTITY_BANNER
        self.assertEqual(driver.classify_identity(banner + b'\n'), 'strict_validated')
        for data in (b'', b'listening only\n', b'prefix ' + banner + b'\n', banner.replace(b'existing_keyfile', b'configured') + b'\n', banner + b'\n' + banner + b'\n'):
            self.assertEqual(driver.classify_identity(data), 'other')
        self.assertEqual(driver.classify_identity(banner + b'\nnode identity generated + persisted to private\n'), 'generated')
    def test_generic_or_wrong_refusal_class_is_insufficient(self):
        modes = ('file','inline','env','ref')
        rows = [f'ONYX_PROFILE {mode} strict socket exe carry pass'.encode() for mode in modes]
        valid = [b'ONYX_REFUSAL key ChangedNodeIdentity retained socket pong', b'ONYX_REFUSAL realm ChangedNodeRealm retained socket pong', b'ONYX_REFUSAL env ChangedBootEnvironment retained socket pong']
        for replacement in (b'ONYX_REFUSAL key retained socket pong', b'ONYX_REFUSAL key SessionReplicaConverging retained socket pong'):
            with self.assertRaises(RuntimeError): driver.profiles_complete(b'\n'.join(rows + [replacement] + valid[1:]), dict.fromkeys(modes))

class ApkPhaseTests(unittest.TestCase):
    def test_fixed_bounded_phase_and_exit(self):
        self.assertEqual(driver.parse_apk_phase(b'ONYX_DIAG apkphase old capability command_failed 126\n'), {'stage':'old','phase':'capability','class':'command_failed','exit':126})
        self.assertIsNone(driver.parse_apk_phase(b''))
        for item in (b'ONYX_DIAG apkphase old capability command_failed 0', b'ONYX_DIAG apkphase old copy missing_token 1', b'ONYX_DIAG apkphase old capability command_failed 256', b'ONYX_DIAG apkphase old capability arbitrary 1', b'ONYX_DIAG apkphase old capability command_failed 126\nONYX_DIAG apkphase old capability command_failed 126'):
            with self.assertRaises(RuntimeError): driver.parse_apk_phase(item)

class SocketDiagnosticTests(unittest.TestCase):
    def test_fixed_initial_counts_only(self):
        row = driver.parse_socket_diagnostic(b'ONYX_DIAG socket file server_absent 0 1 0 2 initial\n')
        self.assertEqual(row, {'mode':'file','stage':'server_absent','tcp4_established':0,'tcp6_established':1,'client_fd_unreadable':0,'server_fd_unreadable':2})
        self.assertIsNone(driver.parse_socket_diagnostic(b''))
        for item in (b'ONYX_DIAG socket file server_absent 1000 0 0 0 initial', b'ONYX_DIAG socket file other 0 0 0 0 initial', b'ONYX_DIAG socket file server_absent 0 0 0 0 initial extra', b'ONYX_DIAG socket file server_absent 0 0 0 0 initial\nONYX_DIAG socket file server_absent 0 0 0 0 initial'):
            with self.assertRaises(RuntimeError): driver.parse_socket_diagnostic(item)

class SocketTableTests(unittest.TestCase):
    def test_dual_stack_table_filter_and_missing_table(self):
        import subprocess
        guest = (Path(__file__).resolve().parent / 'guest.sh').read_text()
        start = guest.index('socket_table_inodes() {')
        end = guest.index('\n}', start) + 2
        function = guest[start:end]
        with tempfile.TemporaryDirectory(dir=Path(__file__).resolve().parents[2]) as tmp:
            root = Path(tmp)
            tcp4, tcp6 = root / 'tcp', root / 'tcp6'
            tcp4.write_text('header\n 0: 00000000:4128 A:2 01 0 0 0 0 0 111\n 1: 00000000:4128 A:2 0A 0 0 0 0 0 222\n')
            tcp6.write_text('header\n 0: 00000000:4128 A:2 01 0 0 0 0 0 333\n 1: 00000000:9999 A:2 01 0 0 0 0 0 444\n')
            cmd = ['sh','-c', function + '\nsocket_table_inodes "$1" "$2"', 'sh', str(tcp4), str(tcp6)]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
            self.assertEqual(result.stdout, b'111\n333\n')
            tcp6.unlink()
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, b'')

if __name__ == '__main__': unittest.main()
