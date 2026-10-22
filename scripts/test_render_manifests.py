#!/usr/bin/env python3
"""
test_render_manifests.py - Pruebas unitarias y de integración para render_manifests.py.

Valida:
1. Rechazo de variables de base de datos vacías o ausentes.
2. Rechazo de sintaxis YAML malformada.
3. Rechazo de residuos de claves PEM no autorizadas.
4. Verificación de almacenamiento PVC (ReadWriteMany en producción).
5. Verificación de EphemeralRsa explícito en Development.
6. Bloqueo de seguridad: EphemeralRsa prohibido en QA y Producción.
7. Renderizado válido de dev con kubectl kustomize.
8. Renderizado sintáctico válido de prod con kubectl kustomize en modo render-only.
9. Gate de despliegue: Detiene la ejecución para QA y Producción antes de transferencia.
"""

import os
import shutil
import tempfile
import unittest

from render_manifests import render_manifests, ENV_CONFIGS


class TestRenderManifests(unittest.TestCase):

    def setUp(self):
        self.env_backup = dict(os.environ)
        # Suministrar credenciales GHCR por defecto para pruebas
        os.environ["GHCR_USERNAME"] = "testuser"
        os.environ["GHCR_TOKEN"] = "testtoken"

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

    def test_yaml_syntax_validation(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            dev_dir = os.path.join(tmp_dir, "dev", "backend")
            os.makedirs(dev_dir)

            bad_yaml = os.path.join(dev_dir, "malformed.yaml")
            with open(bad_yaml, "w", encoding="utf-8") as f:
                f.write("key: [unclosed_bracket\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("Sintaxis YAML inválida", str(ctx.exception))

    def test_pem_residue_is_strictly_rejected(self):
        """Verifica que ningún archivo de manifiestos contenga residuos de claves PEM."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            dev_dir = os.path.join(tmp_dir, "dev", "backend")
            os.makedirs(dev_dir)

            pem_secret = os.path.join(dev_dir, "secret.yaml")
            with open(pem_secret, "w", encoding="utf-8") as f:
                f.write("apiVersion: v1\nkind: Secret\nmetadata:\n  name: s\nstringData:\n  Jwt__PrivateKeyPem: 'residuo'\n")

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("residuo de clave PEM", str(ctx.exception))

    def test_ephemeral_rsa_strictly_forbidden_in_production(self):
        """Verifica que si prod intenta configurar EphemeralRsa, el renderer falle con error crítico."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            # Manipular ConfigMap para intentar habilitar EphemeralRsa en prod
            admin_manifest = os.path.join(tmp_prod, "admin-backend", "admin-backend-manifest.yaml")
            with open(admin_manifest, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace('Jwt__SigningProvider: "PersistentRsa"', 'Jwt__SigningProvider: "EphemeralRsa"')
            with open(admin_manifest, "w", encoding="utf-8") as f:
                f.write(content)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("prod", base_dir=tmp_dir, render_only=True)
            self.assertIn("estrictamente prohibido fuera de Development", str(ctx.exception))

    def test_production_requires_read_write_many_pvc(self):
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            # Modificar a RWO para verificar rechazo
            backend_manifest = os.path.join(tmp_prod, "backend", "backend-manifest.yaml")
            with open(backend_manifest, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace("ReadWriteMany", "ReadWriteOnce")
            with open(backend_manifest, "w", encoding="utf-8") as f:
                f.write(content)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("prod", base_dir=tmp_dir, render_only=True)
            self.assertIn("debe incluir modo de acceso 'ReadWriteMany'", str(ctx.exception))

    def test_valid_render_dev_with_kustomize(self):
        """Prueba de integración: renderiza dev completo y ejecuta kubectl kustomize."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=localhost;Database=dev_ident;"

            render_manifests("dev", base_dir=tmp_dir)

    def test_valid_render_prod_in_render_only_mode(self):
        """Prueba de integración: renderiza prod completo en modo render-only y ejecuta kubectl kustomize."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"

            render_manifests("prod", base_dir=tmp_dir, render_only=True)

    def test_gate_halts_deployment_before_transfer_for_production(self):
        """Demuestra que el gate de seguridad detiene activamente la transferencia para producción con código 2."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_prod = os.path.join(tmp_dir, "prod")
            shutil.copytree(os.path.join(repo_root, "prod"), tmp_prod)

            os.environ["PROD_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ops;"
            os.environ["PROD_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=prod;Database=prod_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("prod", base_dir=tmp_dir, render_only=False)
            self.assertEqual(ctx.exception.code, 2)

    def test_gate_halts_deployment_before_transfer_for_qa(self):
        """Demuestra que el gate de seguridad detiene activamente la transferencia para QA con código 2."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_qa = os.path.join(tmp_dir, "qa")
            shutil.copytree(os.path.join(repo_root, "qa"), tmp_qa)

            os.environ["QA_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=qa;Database=qa_ops;"
            os.environ["QA_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=qa;Database=qa_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("qa", base_dir=tmp_dir, render_only=False)
            self.assertEqual(ctx.exception.code, 2)


    def test_dev_fails_when_rolling_update_overlaps_ephemeral_rsa(self):
        """B-19: Verifica que render_manifests rechace RollingUpdate con maxSurge>0 en dev cuando se usa EphemeralRsa."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        with tempfile.TemporaryDirectory() as tmp_dir:
            tmp_dev = os.path.join(tmp_dir, "dev")
            shutil.copytree(os.path.join(repo_root, "dev"), tmp_dev)

            # Reintroducir la estrategia defectuosa RollingUpdate con maxSurge: 1
            admin_manifest = os.path.join(tmp_dev, "admin-backend", "admin-backend-manifest.yaml")
            with open(admin_manifest, "r", encoding="utf-8") as f:
                content = f.read()

            content = content.replace(
                "strategy:\n    type: Recreate",
                "strategy:\n    type: RollingUpdate\n    rollingUpdate:\n      maxSurge: 1\n      maxUnavailable: 0"
            )
            with open(admin_manifest, "w", encoding="utf-8") as f:
                f.write(content)

            os.environ["DEV_OPERATIONSDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ops;"
            os.environ["DEV_IDENTITYDATABASE_CONNECTIONSTRING"] = "Host=dev;Database=dev_ident;"

            with self.assertRaises(SystemExit) as ctx:
                render_manifests("dev", base_dir=tmp_dir)
            self.assertIn("B-19", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
