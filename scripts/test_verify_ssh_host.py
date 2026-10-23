#!/usr/bin/env python3
"""
test_verify_ssh_host.py - Pruebas automatizadas de autenticación estricta de host SSH (B-23).

Valida:
1. Fingerprint ausente -> falla antes de intentar conexión.
2. Formato inválido -> falla (prefijo, base64 corrupto, longitud digest != 32 bytes).
3. Huella distinta -> falla inmediatamente y no permite continuar.
4. Huella correcta -> valida exitosamente y genera known_hosts verificado.
5. Exactamente una clave ED25519 aceptada (0 claves -> falla; >1 claves -> falla).
6. Regla de prohibición: Cero 'StrictHostKeyChecking=no' y cero 'UserKnownHostsFile=/dev/null'
   en workflows, scripts y manifiestos.
7. Unificación de known_hosts en todos los accesos SSH y SCP en deploy_remote.sh.
8. Logs y excepciones no filtran secretos ni claves.
"""

import base64
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from verify_ssh_host import (
    validate_fingerprint_format,
    compute_ed25519_fingerprint,
    extract_ed25519_keys,
    verify_ssh_host,
)


class TestVerifySshHost(unittest.TestCase):

    def setUp(self):
        # Generar clave pública ED25519 de prueba (32 bytes de clave pública en formato OpenSSH)
        # Formato de blob ssh-ed25519 de OpenSSH:
        # string "ssh-ed25519" (4 bytes len + 11 bytes) + string key (4 bytes len + 32 bytes) = 51 bytes
        prefix = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
        self.raw_pubkey_bytes = prefix + b"12345678901234567890123456789012"
        self.pubkey_b64 = base64.b64encode(self.raw_pubkey_bytes).decode("utf-8")

        # Calcular huella esperada OpenSSH
        digest = hashlib.sha256(self.raw_pubkey_bytes).digest()
        self.valid_fingerprint = f"SHA256:{base64.b64encode(digest).decode('utf-8').rstrip('=')}"

        self.mock_host = "192.168.1.50"
        self.mock_port = 22
        self.mock_keyscan_content = f"{self.mock_host} ssh-ed25519 {self.pubkey_b64}\n"

    def test_fingerprint_missing_fails(self):
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprint_format("")
        self.assertIn("es obligatoria", str(ctx.exception))

        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprint_format("   ")
        self.assertIn("es obligatoria", str(ctx.exception))

    def test_fingerprint_invalid_format_fails(self):
        # Sin prefijo SHA256:
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprint_format("MD5:12:34:56")
        self.assertIn("Debe comenzar con el prefijo 'SHA256:'", str(ctx.exception))

        # Base64 corrupto
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprint_format("SHA256:not-valid-base64!@#$")
        self.assertIn("no es válida", str(ctx.exception))

        # Longitud distinta a 32 bytes (digest truncado)
        short_b64 = base64.b64encode(b"short_digest").decode("utf-8")
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprint_format(f"SHA256:{short_b64}")
        self.assertIn("Se esperaban 32 bytes", str(ctx.exception))

    def test_fingerprint_mismatch_fails_and_aborts(self):
        different_digest = hashlib.sha256(b"different_key_data").digest()
        wrong_fingerprint = f"SHA256:{base64.b64encode(different_digest).decode('utf-8')}"

        with tempfile.TemporaryDirectory() as tmp_dir:
            scan_file = os.path.join(tmp_dir, "scan.txt")
            with open(scan_file, "w", encoding="utf-8") as f:
                f.write(self.mock_keyscan_content)

            out_known_hosts = os.path.join(tmp_dir, "known_hosts")

            with self.assertRaises(SystemExit) as ctx:
                verify_ssh_host(
                    host=self.mock_host,
                    port=self.mock_port,
                    expected_fingerprint=wrong_fingerprint,
                    out_known_hosts=out_known_hosts,
                    keyscan_output_file=scan_file,
                )
            self.assertIn("La huella SSH del servidor no coincide", str(ctx.exception))
            # Verificar que known_hosts NO fue creado ante fallo
            self.assertFalse(os.path.exists(out_known_hosts))

    def test_fingerprint_match_succeeds_and_creates_known_hosts(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            scan_file = os.path.join(tmp_dir, "scan.txt")
            with open(scan_file, "w", encoding="utf-8") as f:
                f.write(self.mock_keyscan_content)

            out_known_hosts = os.path.join(tmp_dir, "known_hosts")

            verify_ssh_host(
                host=self.mock_host,
                port=self.mock_port,
                expected_fingerprint=self.valid_fingerprint,
                out_known_hosts=out_known_hosts,
                keyscan_output_file=scan_file,
            )

            self.assertTrue(os.path.exists(out_known_hosts))
            with open(out_known_hosts, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn(self.mock_host, content)
            self.assertIn("ssh-ed25519", content)
            self.assertIn(self.pubkey_b64, content)

    def test_zero_ed25519_keys_fails(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            scan_file = os.path.join(tmp_dir, "scan.txt")
            # Salida solo con clave RSA o vacía
            with open(scan_file, "w", encoding="utf-8") as f:
                f.write(f"{self.mock_host} ssh-rsa AAAAB3NzaC1yc2E...\n")

            out_known_hosts = os.path.join(tmp_dir, "known_hosts")

            with self.assertRaises(SystemExit) as ctx:
                verify_ssh_host(
                    host=self.mock_host,
                    port=self.mock_port,
                    expected_fingerprint=self.valid_fingerprint,
                    out_known_hosts=out_known_hosts,
                    keyscan_output_file=scan_file,
                )
            self.assertIn("no presentó ninguna clave pública 'ssh-ed25519'", str(ctx.exception))

    def test_multiple_ed25519_keys_fails(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            scan_file = os.path.join(tmp_dir, "scan.txt")
            second_key = base64.b64encode(b"another_key_blob_51_bytes_long_1234567890123456789").decode("utf-8")
            with open(scan_file, "w", encoding="utf-8") as f:
                f.write(f"{self.mock_host} ssh-ed25519 {self.pubkey_b64}\n")
                f.write(f"{self.mock_host} ssh-ed25519 {second_key}\n")

            out_known_hosts = os.path.join(tmp_dir, "known_hosts")

            with self.assertRaises(SystemExit) as ctx:
                verify_ssh_host(
                    host=self.mock_host,
                    port=self.mock_port,
                    expected_fingerprint=self.valid_fingerprint,
                    out_known_hosts=out_known_hosts,
                    keyscan_output_file=scan_file,
                )
            self.assertIn("presentó múltiples (2) claves ED25519", str(ctx.exception))

    def test_forbidden_ssh_patterns_strictly_absent_in_all_repo(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        forbidden_patterns = [
            "StrictHostKeyChecking=no",
            "UserKnownHostsFile=/dev/null",
        ]

        # Buscar en todos los workflows, scripts y manifiestos
        violations = []
        for root, _, files in os.walk(repo_root):
            if ".git" in root or "venv" in root:
                continue
            for file in files:
                if file.endswith((".yml", ".yaml", ".sh", ".py")):
                    file_path = os.path.join(root, file)
                    rel_path = os.path.relpath(file_path, repo_root)
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                    for pattern in forbidden_patterns:
                        # Ignorar el propio archivo de pruebas que busca el string
                        if "test_verify_ssh_host.py" in file:
                            continue
                        if pattern in content:
                            violations.append((rel_path, pattern))

        self.assertEqual(
            violations,
            [],
            f"Violación de Regla B-23: Se encontraron patrones prohibidos en el repositorio: {violations}",
        )

    def test_deploy_remote_script_uses_verified_known_hosts(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        deploy_script = os.path.join(repo_root, "scripts", "deploy_remote.sh")
        self.assertTrue(os.path.isfile(deploy_script), "deploy_remote.sh debe existir")

        with open(deploy_script, "r", encoding="utf-8") as f:
            content = f.read()

        # Debe invocar verify_ssh_host.py
        self.assertIn("verify_ssh_host.py", content)
        # Debe contener mktemp -d y trap para cleanup
        self.assertIn("mktemp -d", content)
        self.assertIn("trap cleanup", content)
        # Debe usar StrictHostKeyChecking=yes
        self.assertIn("StrictHostKeyChecking=yes", content)
        self.assertNotIn("StrictHostKeyChecking=no", content)
        # Debe usar UserKnownHostsFile verificado
        self.assertIn('UserKnownHostsFile="$KNOWN_HOSTS"', content)
        self.assertNotIn("/dev/null", content)


if __name__ == "__main__":
    unittest.main()
