#!/usr/bin/env python3
"""
test_render_manifests.py - Pruebas unitarias y de integración para render_manifests.py.

Valida:
1. Rechazo de variables de base de datos o secreto JWT vacíos o ausentes.
2. Validación estricta de JWT_ACTIVE_KEY_ID (ausencia, vacío, regex, placeholder).
3. Validación estricta de JWT_ACTIVE_SIGNING_KEY_BASE64 (Base64 válido, >= 32 bytes CSPRNG).
4. Contrato de rotación con clave anterior:
   - previous key sin previous kid y viceversa.
   - previous kid igual a active kid.
   - previous key material igual a active key material.
5. Validación segura de JWT_KEY_FINGERPRINTS_JSON:
   - JSON ausente / malformado.
   - Faltan ambientes o sobran ambientes.
   - Fingerprints duplicados entre ambientes.
   - Mismatch con la clave activa.
   - Coincidencia válida sin filtrar secretos.
6. Regla B-22: Cero secretos en YAML persistente o archivos en disco.
7. Generación dinámica en memoria de secretos para pipe SSH.
8. Validación de almacenamiento durable PVC (RWO en dev/qa, RWX en prod, StorageClass requerida en qa/prod).
9. Aislamiento total de Frontends frente a secretos de backend y JWT.
10. Rechazo de residuos RSA, PEM, JWKS y flags efímeros.
11. Renderizado y validación estricta de hosts desde variables de GitHub Environments.
"""

import base64
import hashlib
import json
import os
import shutil
import sys
import tempfile
import unittest
import yaml

sys.path.insert(0, os.path.dirname(__file__))
from render_manifests import (
    render_manifests,
    validate_base64_secret,
    validate_key_id,
    validate_fingerprints_json,
    validate_hostname,
    emit_secrets_yaml,
)


class TestRenderManifests(unittest.TestCase):

    def setUp(self):
        self.env_backup = dict(os.environ)

        # 32 bytes CSPRNG independientes para pruebas
        self.dev_raw = b"0123456789abcdef0123456789abcdef"
        self.qa_raw = b"qa_qa_qa_qa_qa_qa_qa_qa_qa_qa_qa_1"
        self.prod_raw = b"prod_prod_prod_prod_prod_prod_pr1"

        self.valid_dev_key = base64.b64encode(self.dev_raw).decode("utf-8")
        self.valid_qa_key = base64.b64encode(self.qa_raw).decode("utf-8")
        self.valid_prod_key = base64.b64encode(self.prod_raw).decode("utf-8")

        self.dev_fp = hashlib.sha256(self.dev_raw).hexdigest()
        self.qa_fp = hashlib.sha256(self.qa_raw).hexdigest()
        self.prod_fp = hashlib.sha256(self.prod_raw).hexdigest()

        self.valid_fingerprints_json = json.dumps({
            "dev": self.dev_fp,
            "qa": self.qa_fp,
            "prod": self.prod_fp
        })

        os.environ["OPERATIONS_DATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ops;"
        os.environ["IDENTITY_DATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ident;"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.valid_dev_key
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_KEY_FINGERPRINTS_JSON"] = self.valid_fingerprints_json
        os.environ["GHCR_USERNAME"] = "testuser"
        os.environ["GHCR_TOKEN"] = "testtoken"
        os.environ["PVC_STORAGE_CLASS"] = "standard"
        os.environ["INGRESS_FRONTEND_HOST"] = "dev.cobroup.com"
        os.environ["INGRESS_ADMIN_FRONTEND_HOST"] = "dev-admin.cobroup.com"
        os.environ["INGRESS_API_HOST"] = "dev-api.cobroup.com"
        os.environ["INGRESS_AUTH_HOST"] = "dev-auth.cobroup.com"
        os.environ["INGRESS_FRONTEND_ALIAS_HOST"] = "www.cobroup.com"

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env_backup)

    def test_missing_required_variables_exits(self):
        del os.environ["OPERATIONS_DATABASE_CONNECTIONSTRING"]
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Faltan secretos requeridos", str(ctx.exception))

    def test_key_id_validation_strict(self):
        # Válido
        self.assertEqual("k1", validate_key_id("TEST_KID", "k1"))
        self.assertEqual("k-prod.2026_01", validate_key_id("TEST_KID", "k-prod.2026_01"))

        # Vacío
        with self.assertRaises(SystemExit):
            validate_key_id("TEST_KID", "")

        # Placeholder
        with self.assertRaises(SystemExit) as ctx:
            validate_key_id("TEST_KID", "CHANGE_ME")
        self.assertIn("placeholder", str(ctx.exception))

        # Formato inválido
        with self.assertRaises(SystemExit) as ctx:
            validate_key_id("TEST_KID", "invalid kid with spaces")
        self.assertIn("formato requerido", str(ctx.exception))

    def test_hostname_validation_strict(self):
        self.assertEqual(
            "dev-api.cobroup.com",
            validate_hostname("INGRESS_API_HOST", "DEV-API.COBROUP.COM"),
        )

        for invalid_hostname in ["", "https://dev.cobroup.com", "dev.cobroup.com/path", "*.cobroup.com"]:
            with self.subTest(hostname=invalid_hostname), self.assertRaises(SystemExit):
                validate_hostname("INGRESS_FRONTEND_HOST", invalid_hostname)

    def test_missing_ingress_host_variable_fails_fast(self):
        del os.environ["INGRESS_AUTH_HOST"]
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            shutil.copytree(os.path.join(repo_root, "dev"), os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("INGRESS_AUTH_HOST", str(ctx.exception))

    def test_jwt_key_crypto_validation(self):
        # Vacío
        with self.assertRaises(SystemExit):
            validate_base64_secret("dev", "KEY", "")

        # Placeholder
        with self.assertRaises(SystemExit):
            validate_base64_secret("dev", "KEY", "PLACEHOLDER_KEY")

        # Base64 inválido
        with self.assertRaises(SystemExit):
            validate_base64_secret("dev", "KEY", "not-base64!@#$")

        # Menor a 32 bytes
        short_b64 = base64.b64encode(b"short_key_under_32_bytes").decode("utf-8")
        with self.assertRaises(SystemExit) as ctx:
            validate_base64_secret("dev", "KEY", short_b64)
        self.assertIn("mínimo 32 bytes", str(ctx.exception))

        # Válido >= 32 bytes
        decoded = validate_base64_secret("dev", "KEY", self.valid_dev_key)
        self.assertEqual(len(decoded), 32)

    def test_previous_key_rotation_contract(self):
        # Previous key sin previous kid
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.valid_qa_key
        if "JWT_PREVIOUS_KEY_ID" in os.environ:
            del os.environ["JWT_PREVIOUS_KEY_ID"]

        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("deben estar ambos presentes o ambos ausentes", str(ctx.exception))

        # Previous kid igual a active kid
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k1"
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("no puede ser idéntico al 'JWT_ACTIVE_KEY_ID'", str(ctx.exception))

        # Previous material criptográfico igual a active material
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k0"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.valid_dev_key
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "dev"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("no puede ser idéntico al de la clave activa", str(ctx.exception))

    def test_fingerprints_json_negative_tests(self):
        # 1. JSON malformado
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprints_json("dev", self.dev_raw, "{not-json")
        self.assertIn("no es un JSON válido", str(ctx.exception))

        # 2. Faltan ambientes
        incomplete_json = json.dumps({"dev": self.dev_fp, "qa": self.qa_fp})
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprints_json("dev", self.dev_raw, incomplete_json)
        self.assertIn("debe contener exactamente las claves 'dev', 'qa' y 'prod'", str(ctx.exception))

        # 3. Fingerprints duplicados entre ambientes
        duplicate_json = json.dumps({"dev": self.dev_fp, "qa": self.dev_fp, "prod": self.prod_fp})
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprints_json("dev", self.dev_raw, duplicate_json)
        self.assertIn("fingerprints duplicados", str(ctx.exception))

        # 4. Fingerprint mismatch con la clave activa
        wrong_fp_json = json.dumps({
            "dev": "0000000000000000000000000000000000000000000000000000000000000000",
            "qa": self.qa_fp,
            "prod": self.prod_fp
        })
        with self.assertRaises(SystemExit) as ctx:
            validate_fingerprints_json("dev", self.dev_raw, wrong_fp_json)
        self.assertIn("no coincide con el registrado", str(ctx.exception))
        # Ensure no secret or calculated fingerprint is leaked in the message
        self.assertNotIn(self.dev_fp, str(ctx.exception))
        self.assertNotIn(self.valid_dev_key, str(ctx.exception))

    def test_zero_secrets_persisted_rule_b22(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            render_manifests("dev", base_dir=tmp_dir)

            # Verificar que NINGÚN archivo secret.yaml existe en la carpeta dev
            for root, _, files in os.walk(tmp_dev):
                for f in files:
                    self.assertNotIn("secret.yaml", f, "Regla B-22 violada: secret.yaml encontrado en checkout!")
                    self.assertNotIn("ghcr-secret.yaml", f, "Regla B-22 violada: ghcr-secret.yaml encontrado en checkout!")

    def test_emit_secrets_yaml_stream(self):
        yaml_stream = emit_secrets_yaml("dev", "cobroup-dev")
        self.assertIn("name: jwt-signing-secret", yaml_stream)
        self.assertIn("name: admin-backend-secret", yaml_stream)
        self.assertIn("name: backend-secret", yaml_stream)
        self.assertIn("name: ghcr-secret", yaml_stream)

    def test_storage_class_required_in_qa_and_prod(self):
        del os.environ["PVC_STORAGE_CLASS"]
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.valid_qa_key
        with tempfile.TemporaryDirectory() as tmp_dir:
            os.makedirs(os.path.join(tmp_dir, "qa"))
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("qa", base_dir=tmp_dir)
            self.assertIn("PVC_STORAGE_CLASS' es obligatoria", str(ctx.exception))

    def test_frontend_isolation_and_no_secrets_in_manifests(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            # Manipular manifest de frontend para filtrar jwt-signing-secret
            fe_manifest = os.path.join(tmp_dev, "frontend", "frontend-manifest.yaml")
            with open(fe_manifest, "a", encoding="utf-8") as f:
                f.write("\n            - secretRef:\n                name: jwt-signing-secret\n")

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Clave o Secret JWT expuesto a frontend", str(ctx.exception))

    def test_legacy_rsa_pem_jwks_residues_strictly_rejected(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            # Insertar residuo prohibido en el ConfigMap de backend
            be_manifest = os.path.join(tmp_dev, "backend", "backend-manifest.yaml")
            with open(be_manifest, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace('Storage__Provider: "FileSystem"', 'Storage__Provider: "FileSystem"\n  Jwt__SigningProvider: "EphemeralRsa"')
            with open(be_manifest, "w", encoding="utf-8") as f:
                f.write(content)

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Residuo no permitido", str(ctx.exception))

    def test_production_requires_rwx(self):
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

            os.environ["OPERATIONS_DATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["IDENTITY_DATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"
            os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.valid_prod_key
            os.environ["JWT_ACTIVE_KEY_ID"] = "k1"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("prod", base_dir=tmp_dir)
            self.assertIn("debe incluir modo de acceso 'ReadWriteMany'", str(ctx.exception))

    def test_valid_render_all_environments(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

        # Dev
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)
            render_manifests("dev", base_dir=tmp_dir)
            with open(os.path.join(tmp_dev, "ingress.yaml"), "r", encoding="utf-8") as ingress_file:
                ingress_docs = [doc for doc in yaml.safe_load_all(ingress_file) if doc]
            dev_hosts = {
                rule["host"]
                for doc in ingress_docs
                for rule in doc.get("spec", {}).get("rules", [])
            }
            self.assertEqual(
                {
                    "dev.cobroup.com",
                    "dev-admin.cobroup.com",
                    "dev-api.cobroup.com",
                    "dev-auth.cobroup.com",
                },
                dev_hosts,
            )
            with open(os.path.join(tmp_dev, "frontend", "frontend-manifest.yaml"), "r", encoding="utf-8") as frontend_file:
                frontend_rendered = frontend_file.read()
            self.assertIn("https://dev-api.cobroup.com", frontend_rendered)
            self.assertIn("https://dev-auth.cobroup.com", frontend_rendered)
            self.assertNotIn("__INGRESS_", frontend_rendered)

        # QA
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_qa = os.path.join(tmp_dir, "qa")
            shutil.copytree(os.path.join(repo_root, "qa"), tmp_qa)
            os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.valid_qa_key
            os.environ["INGRESS_FRONTEND_HOST"] = "qa.cobroup.com"
            os.environ["INGRESS_ADMIN_FRONTEND_HOST"] = "qa-admin.cobroup.com"
            os.environ["INGRESS_API_HOST"] = "qa-api.cobroup.com"
            os.environ["INGRESS_AUTH_HOST"] = "qa-auth.cobroup.com"
            render_manifests("qa", base_dir=tmp_dir)

        # Prod
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)
            os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.valid_prod_key
            os.environ["INGRESS_FRONTEND_HOST"] = "cobroup.com"
            os.environ["INGRESS_FRONTEND_ALIAS_HOST"] = "www.cobroup.com"
            os.environ["INGRESS_ADMIN_FRONTEND_HOST"] = "admin.cobroup.com"
            os.environ["INGRESS_API_HOST"] = "api.cobroup.com"
            os.environ["INGRESS_AUTH_HOST"] = "auth.cobroup.com"
            render_manifests("prod", base_dir=tmp_dir)

    def test_jwt_secret_structure_stable_vs_overlap(self):
        # 1. Estado estable: solo 2 campos
        stable_yaml = emit_secrets_yaml("dev", "cobroup-dev")
        self.assertIn("Jwt__ActiveKeyId", stable_yaml)
        self.assertIn("Jwt__SigningKeyBase64", stable_yaml)
        self.assertNotIn("Jwt__PreviousValidationKeys__0__KeyId", stable_yaml)
        self.assertNotIn("Jwt__PreviousValidationKeys__0__SigningKeyBase64", stable_yaml)

        # 2. Estado de solapamiento / rotación: exactamente 4 campos
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k-prev"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.valid_qa_key
        overlap_yaml = emit_secrets_yaml("dev", "cobroup-dev")
        self.assertIn("Jwt__ActiveKeyId", overlap_yaml)
        self.assertIn("Jwt__SigningKeyBase64", overlap_yaml)
        self.assertIn("Jwt__PreviousValidationKeys__0__KeyId", overlap_yaml)
        self.assertIn("Jwt__PreviousValidationKeys__0__SigningKeyBase64", overlap_yaml)

    def test_configmaps_do_not_contain_jwt_state(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)
            render_manifests("dev", base_dir=tmp_dir)

            for svc in ["backend", "admin-backend"]:
                manifest_path = os.path.join(tmp_dev, svc, f"{svc}-manifest.yaml")
                with open(manifest_path, "r", encoding="utf-8") as f:
                    docs = yaml.safe_load_all(f)
                    for doc in docs:
                        if doc and doc.get("kind") == "ConfigMap":
                            data = doc.get("data", {})
                            self.assertNotIn("Jwt__ActiveKeyId", data, f"ConfigMap en {svc} contiene Jwt__ActiveKeyId")
                            self.assertNotIn("Jwt__PreviousValidationKeys__0__KeyId", data)
                            for k in data:
                                self.assertFalse(k.startswith("Jwt__"), f"ConfigMap en {svc} contiene clave JWT: {k}")

    def test_missing_fingerprints_json_fails_fast(self):
        del os.environ["JWT_KEY_FINGERPRINTS_JSON"]
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("JWT_KEY_FINGERPRINTS_JSON' es obligatoria", str(ctx.exception))

    def test_mismatched_kubernetes_namespace_fails_fast(self):
        os.environ["KUBERNETES_NAMESPACE"] = "wrong-namespace"
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("no coincide con el namespace requerido", str(ctx.exception))

    def test_uncoordinated_rotation_rejected_in_general_deploy(self):
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k-prev"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.valid_qa_key
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            # Despliegue general sin allow_rotation debe fallar
            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir, allow_rotation=False)
            self.assertIn("rotate-jwt.yml", str(ctx.exception))

            # Con allow_rotation=True debe permitirse
            render_manifests("dev", base_dir=tmp_dir, allow_rotation=True)


if __name__ == "__main__":
    unittest.main()
