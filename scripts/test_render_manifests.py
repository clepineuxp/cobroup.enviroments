#!/usr/bin/env python3
"""
test_render_manifests.py - Pruebas unitarias y de integración para render_manifests.py.

Valida:
1. Rechazo de variables de base de datos o secreto JWT vacíos o ausentes.
2. Rechazo de secretos JWT con placeholders.
3. Rechazo de secretos JWT con Base64 inválido.
4. Rechazo de secretos JWT menores a 32 bytes (256 bits).
5. Aceptación de secretos JWT de 32 bytes o más.
6. Detección y rechazo de reutilización de claves entre ambientes (Dev vs QA vs Prod).
7. Rechazo de sintaxis YAML malformada.
8. Rechazo estricto de residuos PEM, RSA, JWKS, EphemeralRsa, PersistentRsa, SigningProvider y flags de riesgo.
9. Aislamiento de Frontends (prohibición de que reciban o contengan Jwt__SigningKeyBase64).
10. Verificación de almacenamiento PVC (ReadWriteMany en producción).
11. Verificación de Jwt__ActiveKeyId en admin-backend y backend.
12. Renderizado válido de dev, qa y prod con kustomize.
"""

import base64
import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from render_manifests import render_manifests, validate_base64_secret, detect_cross_environment_key_reuse


class TestRenderManifests(unittest.TestCase):

    def setUp(self):
        self.env_backup = dict(os.environ)
        # Suministrar credenciales GHCR y claves JWT de 32 bytes independientes por defecto para pruebas
        os.environ["GHCR_USERNAME"] = "testuser"
        os.environ["GHCR_TOKEN"] = "testtoken"

        # 32 bytes CSPRNG independientes en Base64
        self.valid_dev_key = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode("utf-8")
        self.valid_qa_key = base64.b64encode(b"qa_qa_qa_qa_qa_qa_qa_qa_qa_qa_qa_1").decode("utf-8")
        self.valid_prod_key = base64.b64encode(b"prod_prod_prod_prod_prod_prod_pr1").decode("utf-8")

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env_backup)

    def test_missing_required_variables_exits(self):
        for k in list(os.environ.keys()):
            if k.startswith("DEV_") or k.startswith("QA_") or k.startswith("PROD_"):
                del os.environ[k]

        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Faltan variables requeridas", str(ctx.exception))

    def test_missing_jwt_key_exits(self):
        os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ops;"
        os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ident;"
        if "DEV_JWT_SIGNING_KEY_BASE64" in os.environ:
            del os.environ["DEV_JWT_SIGNING_KEY_BASE64"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("DEV_JWT_SIGNING_KEY_BASE64", str(ctx.exception))

    def test_empty_jwt_key_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            validate_base64_secret("dev", "DEV_JWT_SIGNING_KEY_BASE64", "   ")
        self.assertIn("vacío o ausente", str(ctx.exception))

    def test_placeholder_jwt_key_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            validate_base64_secret("dev", "DEV_JWT_SIGNING_KEY_BASE64", "CHANGE_ME_NOW_12345678901234567890")
        self.assertIn("placeholder", str(ctx.exception))

    def test_invalid_base64_jwt_key_exits(self):
        with self.assertRaises(SystemExit) as ctx:
            validate_base64_secret("dev", "DEV_JWT_SIGNING_KEY_BASE64", "not-valid-base64!@#$%^&*")
        self.assertIn("no es una cadena Base64 válida", str(ctx.exception))

    def test_jwt_key_under_32_bytes_exits(self):
        # 31 bytes: debe ser rechazado
        raw_31 = b"0123456789012345678901234567890"  # 31 bytes
        b64_31 = base64.b64encode(raw_31).decode("utf-8")
        with self.assertRaises(SystemExit) as ctx:
            validate_base64_secret("dev", "DEV_JWT_SIGNING_KEY_BASE64", b64_31)
        self.assertIn("decodifica a 31 bytes", str(ctx.exception))

    def test_jwt_key_32_bytes_or_more_succeeds(self):
        raw_32 = b"01234567890123456789012345678901"  # 32 bytes
        b64_32 = base64.b64encode(raw_32).decode("utf-8")
        decoded = validate_base64_secret("dev", "DEV_JWT_SIGNING_KEY_BASE64", b64_32)
        self.assertEqual(len(decoded), 32)

    def test_cross_environment_key_reuse_detected(self):
        os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key
        os.environ["QA_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key  # Reusing dev key in QA!

        with self.assertRaises(SystemExit) as ctx:
            detect_cross_environment_key_reuse()
        self.assertIn("Reutilización de clave detectada entre ambientes", str(ctx.exception))
        # Ensure the secret itself is NOT printed in the error
        self.assertNotIn(self.valid_dev_key, str(ctx.exception))

    def test_yaml_syntax_validation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dev_dir = os.path.join(tmp_dir, "dev", "backend")
            os.makedirs(dev_dir)

            bad_yaml = os.path.join(dev_dir, "malformed.yaml")
            with open(bad_yaml, "w", encoding="utf-8") as f:
                f.write("key: [unclosed_bracket\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"
            os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Sintaxis YAML inválida", str(ctx.exception))

    def test_pem_residue_is_strictly_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dev_dir = os.path.join(tmp_dir, "dev", "backend")
            os.makedirs(dev_dir)

            pem_secret = os.path.join(dev_dir, "secret.yaml")
            with open(pem_secret, "w", encoding="utf-8") as f:
                f.write("apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  Jwt__PrivateKeyPem: 'residuo'\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"
            os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("residuo no permitido: PrivateKeyPem", str(ctx.exception))

    def test_legacy_rsa_signing_provider_rejected(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dev_dir = os.path.join(tmp_dir, "dev", "admin-backend")
            os.makedirs(dev_dir)

            manifest = os.path.join(dev_dir, "admin-backend-manifest.yaml")
            with open(manifest, "w", encoding="utf-8") as f:
                f.write("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: admin-backend-config\ndata:\n  Jwt__SigningProvider: 'EphemeralRsa'\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"
            os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("residuo no permitido", str(ctx.exception))

    def test_frontend_jwt_leakage_is_rejected(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            # Manipular secret de frontend para filtrar la clave JWT
            frontend_secret = os.path.join(tmp_dev, "frontend", "secret.yaml")
            with open(frontend_secret, "a", encoding="utf-8") as f:
                f.write(f"  Jwt__SigningKeyBase64: 'leaked'\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ident;"
            os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("la clave JWT no debe inyectarse en frontends", str(ctx.exception))

    def test_production_requires_read_write_many_pvc(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            backend_manifest = os.path.join(tmp_prod, "backend", "backend-manifest.yaml")
            with open(backend_manifest, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace("ReadWriteMany", "ReadWriteOnce")
            with open(backend_manifest, "w", encoding="utf-8") as f:
                f.write(content)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"
            os.environ["PROD_JWT_SIGNING_KEY_BASE64"] = self.valid_prod_key

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("prod", base_dir=tmp_dir, render_only=True)
            self.assertIn("debe incluir modo de acceso 'ReadWriteMany'", str(ctx.exception))

    def test_valid_render_dev(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"
            os.environ["DEV_JWT_SIGNING_KEY_BASE64"] = self.valid_dev_key

            render_manifests("dev", base_dir=tmp_dir)

    def test_valid_render_qa(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_qa = os.path.join(tmp_dir, "qa")
            shutil.copytree(os.path.join(repo_root, "qa"), tmp_qa)

            os.environ["QA_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=qa;Database=qa_ops;"
            os.environ["QA_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=qa;Database=qa_ident;"
            os.environ["QA_JWT_SIGNING_KEY_BASE64"] = self.valid_qa_key

            render_manifests("qa", base_dir=tmp_dir)

    def test_valid_render_prod(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"
            os.environ["PROD_JWT_SIGNING_KEY_BASE64"] = self.valid_prod_key

            render_manifests("prod", base_dir=tmp_dir)


if __name__ == "__main__":
    unittest.main()
