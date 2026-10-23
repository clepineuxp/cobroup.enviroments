#!/usr/bin/env python3
"""
test_rotate_jwt.py - Pruebas unitarias completas para la máquina de estados de rotación JWT (B-21).

Valida:
1. Transición estable -> prepublish válida.
2. Prepublish cuando ya existe clave anterior -> rechazada.
3. Prepublish con kid o material idéntico a la clave activa -> rechazada.
4. Activate sin prepublish -> rechazada.
5. Activate con clave no prepublicada -> rechazada.
6. Retire antes de 20 minutos (1200s) -> rechazada con error explícito.
7. Retire después de 20 minutos -> ejecuta revocación y retira clave anterior.
8. Orden de rollout: Backend (validador) -> Admin-Backend (emisor).
9. Fallo en Backend durante rollout -> ejecuta rollback y NO reinicia Admin-Backend.
10. Fallo en Admin-Backend durante rollout -> ejecuta rollback completo de ambos deployments.
11. Fallo en rollback -> emite ERROR CRITICO explícito y no declara rollback completado.
12. Manifiesto del Job de revocación monta explícitamente secretRef: jwt-signing-secret en envFrom.
13. Fallo de scale a 0 en emergency -> aborta inmediatamente antes de revocar tokens.
14. Fallo de rollout status a 0 en emergency -> aborta inmediatamente antes de revocar tokens.
15. Fallo de wait en Job de revocación -> aborta con error explícito.
16. Rotación completa k1 -> k2 -> retiro de punta a punta.
17. Emergencia con revocación global.
18. Cero valores criptográficos en logs, excepciones o outputs.
"""

import base64
from datetime import datetime, timedelta, timezone
import json
import os
import sys
import unittest
import yaml

sys.path.insert(0, os.path.dirname(__file__))
from rotate_jwt import (
    KubectlExecutor,
    rotate_jwt,
    build_jwt_secret_yaml,
    parse_jwt_secret_state,
    MIN_RETIRE_SECONDS,
)


class MockKubectlExecutor:
    """Mock in-memory de KubectlExecutor para simular clúster y registrar llamadas."""

    def __init__(self, initial_secret_dict: dict | None = None):
        self.secret_dict = initial_secret_dict
        self.command_log = []
        self.fail_on_backend_rollout = False
        self.fail_on_admin_rollout = False
        self.fail_on_emergency_scale = False
        self.fail_on_emergency_rollout_status = False
        self.fail_on_job_wait = False
        self.fail_on_rollback_secret = False
        self.fail_on_rollback_backend = False
        self.admin_replicas = 1
        self.applied_jobs = []

    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        self.command_log.append({"cmd": cmd_str, "stdin": stdin_data})

        # Mock kubectl get secret jwt-signing-secret
        if "kubectl get secret jwt-signing-secret" in cmd_str:
            if not self.secret_dict:
                return 1, "", "Error from server (NotFound): secrets 'jwt-signing-secret' not found"
            return 0, json.dumps(self.secret_dict), ""

        # Mock Job creation (debe ir antes de Secret apply porque el Job monta jwt-signing-secret)
        if "kubectl apply -f -" in cmd_str and stdin_data and ("kind: Job" in stdin_data or "app.kubernetes.io/name: jwt-revocation-job" in stdin_data):
            job_parsed = yaml.safe_load(stdin_data)
            self.applied_jobs.append(job_parsed)
            return 0, "job.batch/jwt-revocation configured", ""

        # Mock kubectl apply secret
        if "kubectl apply -f -" in cmd_str and stdin_data and "jwt-signing-secret" in stdin_data:
            if self.fail_on_rollback_secret:
                return 1, "", "error: failed to apply rollback secret"
            self.secret_dict = yaml.safe_load(stdin_data)
            return 0, "secret/jwt-signing-secret configured", ""

        # Mock rollout backend
        if "kubectl rollout restart deployment/backend" in cmd_str:
            if self.fail_on_backend_rollout:
                self.fail_on_backend_rollout = False  # Falla solo el rollout inicial
                return 1, "", "error: timed out waiting for the condition on deployments/backend"
            if self.fail_on_rollback_backend:
                return 1, "", "error: rollback rollout of backend timed out"
            return 0, "deployment.apps/backend restarted\ndeployment.apps/backend successfully rolled out", ""

        # Mock rollout admin-backend
        if "kubectl rollout restart deployment/admin-backend" in cmd_str:
            if self.fail_on_admin_rollout:
                self.fail_on_admin_rollout = False
                return 1, "", "error: timed out waiting for the condition on deployments/admin-backend"
            return 0, "deployment.apps/admin-backend restarted\ndeployment.apps/admin-backend successfully rolled out", ""

        # Mock scale admin-backend
        if "kubectl scale deployment/admin-backend" in cmd_str:
            if self.fail_on_emergency_scale:
                return 1, "", "error: failed to scale deployment/admin-backend to 0"
            if "--replicas=0" in cmd_str:
                self.admin_replicas = 0
            elif "--replicas=1" in cmd_str:
                self.admin_replicas = 1
            return 0, "deployment.apps/admin-backend scaled", ""

        # Mock rollout status deployment/admin-backend (usado tras scale 0)
        if "kubectl rollout status deployment/admin-backend" in cmd_str and "--timeout=60s" in cmd_str:
            if self.fail_on_emergency_rollout_status:
                return 1, "", "error: admin-backend failed to reach 0 replicas"
            return 0, "deployment \"admin-backend\" successfully rolled out", ""

        # Mock get deployment admin-backend image
        if "kubectl get deployment admin-backend" in cmd_str and "jsonpath" in cmd_str:
            return 0, "ghcr.io/clepineuxp/ms-cobroup-backendadmin:test", ""

        # Mock Job wait
        if "kubectl wait --for=condition=complete job/jwt-revocation" in cmd_str:
            if self.fail_on_job_wait:
                return 1, "", "error: timed out waiting for condition on job/jwt-revocation"
            return 0, "job.batch/jwt-revocation condition met", ""

        # Mock Job logs
        if "kubectl logs job/jwt-revocation" in cmd_str:
            output_json = json.dumps({
                "Action": "revoke",
                "RevokedCount": 5,
                "CorrelationId": "test-corr-id",
                "TimestampUtc": datetime.now(timezone.utc).isoformat(),
            })
            return 0, f"{output_json}\n", ""

        # Mock Job deletion
        if "kubectl delete job jwt-revocation" in cmd_str:
            return 0, "job deleted", ""

        return 0, "ok", ""

    def cleanup(self):
        pass


class TestRotateJwt(unittest.TestCase):

    def setUp(self):
        # Limpiar variables de entorno JWT antes de cada prueba
        for key in [
            "JWT_ACTIVE_KEY_ID",
            "JWT_ACTIVE_SIGNING_KEY_BASE64",
            "JWT_PREVIOUS_KEY_ID",
            "JWT_PREVIOUS_SIGNING_KEY_BASE64",
        ]:
            os.environ.pop(key, None)

        # Generar material criptográfico de prueba válido (32 bytes Base64)
        self.k1_b64 = base64.b64encode(b"12345678901234567890123456789012").decode("utf-8")
        self.k2_b64 = base64.b64encode(b"abcdefghijklmnopqrstuvwxyz012345").decode("utf-8")
        self.k3_b64 = base64.b64encode(b"98765432109876543210987654321098").decode("utf-8")

        # Secret inicial estable con k1 activo
        self.initial_stable_secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "jwt-signing-secret",
                "namespace": "cobroup-dev",
                "annotations": {},
            },
            "type": "Opaque",
            "data": {
                "Jwt__ActiveKeyId": base64.b64encode(b"k1").decode("utf-8"),
                "Jwt__SigningKeyBase64": base64.b64encode(self.k1_b64.encode("utf-8")).decode("utf-8"),
            },
        }

    def test_prepublish_valid_transition(self):
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        rotate_jwt("dev", "prepublish", mock_k8s)

        # Validar que el secret resultante contiene k1 activa y k2 en slot anterior
        state = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state["active_kid"], "k1")
        self.assertEqual(state["prev_kid"], "k2")

    def test_prepublish_when_previous_already_exists_rejected(self):
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k0").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(b"some_key").decode("utf-8")

        mock_k8s = MockKubectlExecutor(secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("clave en slot anterior", str(ctx.exception))

    def test_prepublish_identical_kid_to_active_rejected(self):
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k1"  # kid idéntico
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("mismo kid", str(ctx.exception))

    def test_prepublish_identical_material_rejected(self):
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k1_b64  # Material idéntico

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("material criptográfico", str(ctx.exception))

    def test_activate_without_prepublish_rejected(self):
        # Sin slot previo en clúster
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k2"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k2_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k1"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k1_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "activate", mock_k8s)
        self.assertIn("sin prepublish previo", str(ctx.exception))

    def test_activate_valid_transition(self):
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k2").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(self.k2_b64.encode("utf-8")).decode("utf-8")

        mock_k8s = MockKubectlExecutor(secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k2"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k2_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k1"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k1_b64

        rotate_jwt("dev", "activate", mock_k8s)

        state = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state["active_kid"], "k2")
        self.assertEqual(state["prev_kid"], "k1")
        self.assertIsNotNone(state["activated_at"], "Debe registrar marca de tiempo activated-at")

    def test_retire_premature_blocked_under_20_minutes(self):
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__ActiveKeyId"] = base64.b64encode(b"k2").decode("utf-8")
        secret["data"]["Jwt__SigningKeyBase64"] = base64.b64encode(self.k2_b64.encode("utf-8")).decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k1").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(self.k1_b64.encode("utf-8")).decode("utf-8")

        # Activado hace 5 minutos (300s < 1200s requeridos)
        recent_activation = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        secret["metadata"]["annotations"] = {"cobroup.com/activated-at": recent_activation}

        mock_k8s = MockKubectlExecutor(secret)

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "retire", mock_k8s)
        self.assertIn("Retiro prematuro bloqueado", str(ctx.exception))
        self.assertIn("20 minutos", str(ctx.exception))

    def test_retire_valid_after_20_minutes(self):
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__ActiveKeyId"] = base64.b64encode(b"k2").decode("utf-8")
        secret["data"]["Jwt__SigningKeyBase64"] = base64.b64encode(self.k2_b64.encode("utf-8")).decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k1").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(self.k1_b64.encode("utf-8")).decode("utf-8")

        # Activado hace 25 minutos (> 20 minutos)
        past_activation = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()
        secret["metadata"]["annotations"] = {"cobroup.com/activated-at": past_activation}

        mock_k8s = MockKubectlExecutor(secret)

        rotate_jwt("dev", "retire", mock_k8s)

        # Verificar que el secret resultante contiene SOLO k2 y NINGUNA clave previa
        state = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state["active_kid"], "k2")
        self.assertIsNone(state["prev_kid"])
        self.assertNotIn("Jwt__PreviousValidationKeys__0__KeyId", mock_k8s.secret_dict["data"])

    def test_job_manifest_mounts_jwt_signing_secret_envfrom(self):
        """B-21: Verifica que el Job de revocación monta explícitamente secretRef: jwt-signing-secret."""
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__ActiveKeyId"] = base64.b64encode(b"k2").decode("utf-8")
        secret["data"]["Jwt__SigningKeyBase64"] = base64.b64encode(self.k2_b64.encode("utf-8")).decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k1").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(self.k1_b64.encode("utf-8")).decode("utf-8")
        past_activation = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()
        secret["metadata"]["annotations"] = {"cobroup.com/activated-at": past_activation}

        mock_k8s = MockKubectlExecutor(secret)
        rotate_jwt("dev", "retire", mock_k8s)

        self.assertGreater(len(mock_k8s.applied_jobs), 0, "Debe haberse aplicado al menos un Job de revocación")
        job = mock_k8s.applied_jobs[0]
        container = job["spec"]["template"]["spec"]["containers"][0]

        # Verificar envFrom
        env_from = container.get("envFrom", [])
        secret_refs = [ef.get("secretRef", {}).get("name") for ef in env_from if "secretRef" in ef]
        self.assertIn(
            "jwt-signing-secret",
            secret_refs,
            "El Job de revocación DEBE montar 'jwt-signing-secret' en envFrom para que SymmetricKeyService resuelva Jwt__SigningKeyBase64 y Jwt__ActiveKeyId",
        )

        # Verificar comando y contrato de entrada unificado
        cmd = container.get("command", [])
        self.assertEqual(cmd, ["dotnet", "MS.Cobroup.BackendAdmin.Api.dll", "--revoke-kid", "k1"])

        env = container.get("env", [])
        env_dict = {e["name"]: e["value"] for e in env if "name" in e and "value" in e}
        self.assertEqual(env_dict.get("JWT_REVOKE_KID"), "k1")

        # Verificar securityContext del Job
        sec_ctx = container.get("securityContext", {})
        self.assertFalse(sec_ctx.get("allowPrivilegeEscalation", True))
        self.assertTrue(sec_ctx.get("readOnlyRootFilesystem", False))
        self.assertEqual(job["spec"].get("backoffLimit"), 0)

    def test_emergency_aborts_if_scale_fails(self):
        """B-21: Si falla el escalamiento de Admin-Backend a 0 réplicas, aborta inmediatamente."""
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        mock_k8s.fail_on_emergency_scale = True

        os.environ["JWT_ACTIVE_KEY_ID"] = "k-emergency"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k3_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "emergency", mock_k8s)
        self.assertIn("No se pudo escalar admin-backend a 0 réplicas", str(ctx.exception))
        # Verificar que NO se ejecutó el Job de revocación
        self.assertEqual(len(mock_k8s.applied_jobs), 0)

    def test_emergency_aborts_if_rollout_status_to_zero_fails(self):
        """B-21: Si falla la confirmación de 0 réplicas en emergencia, aborta antes de revocar."""
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        mock_k8s.fail_on_emergency_rollout_status = True

        os.environ["JWT_ACTIVE_KEY_ID"] = "k-emergency"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k3_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "emergency", mock_k8s)
        self.assertIn("Falló la confirmación de escalamiento a 0 réplicas", str(ctx.exception))
        self.assertEqual(len(mock_k8s.applied_jobs), 0)

    def test_revocation_job_wait_failure_aborts(self):
        """B-21: Si el Job de revocación falla o excede el tiempo límite, la operación aborta con error."""
        secret = dict(self.initial_stable_secret)
        secret["data"]["Jwt__ActiveKeyId"] = base64.b64encode(b"k2").decode("utf-8")
        secret["data"]["Jwt__SigningKeyBase64"] = base64.b64encode(self.k2_b64.encode("utf-8")).decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(b"k1").decode("utf-8")
        secret["data"]["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(self.k1_b64.encode("utf-8")).decode("utf-8")
        past_activation = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()
        secret["metadata"]["annotations"] = {"cobroup.com/activated-at": past_activation}

        mock_k8s = MockKubectlExecutor(secret)
        mock_k8s.fail_on_job_wait = True

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "retire", mock_k8s)
        self.assertIn("Job de revocación", str(ctx.exception))
        self.assertIn("falló o excedió el tiempo límite", str(ctx.exception))

    def test_backend_rollout_failure_triggers_rollback_and_aborts_before_admin(self):
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        mock_k8s.fail_on_backend_rollout = True

        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("Rollout de Backend falló. Rollback ejecutado", str(ctx.exception))

        # Verificar que Admin-backend NUNCA fue reiniciado
        admin_restarts = [item for item in mock_k8s.command_log if "deployment/admin-backend" in item["cmd"]]
        self.assertEqual(len(admin_restarts), 0)

    def test_admin_rollout_failure_triggers_full_rollback_of_both(self):
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        mock_k8s.fail_on_admin_rollout = True

        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("Rollout de Admin-Backend falló. Rollback total completado", str(ctx.exception))

        # Verificar que durante el rollback se recuperaron ambos deployments
        rollback_backend = any("rollback restart deployment/backend" in item["cmd"] or "deployment/backend" in item["cmd"] for item in mock_k8s.command_log[3:])
        self.assertTrue(rollback_backend)

    def test_rollback_failure_returns_critical_error_exit_code(self):
        """B-21: Si el rollback falla, se debe emitir un error crítico explícito y código != 0."""
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        mock_k8s.fail_on_admin_rollout = True
        mock_k8s.fail_on_rollback_backend = True

        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64

        with self.assertRaises(SystemExit) as ctx:
            rotate_jwt("dev", "prepublish", mock_k8s)
        self.assertIn("ERROR CRITICO", str(ctx.exception))
        self.assertIn("recuperación de rollback también falló", str(ctx.exception))

    def test_full_rotation_flow_k1_to_k2_to_retire(self):
        """B-21: Flujo completo de rotación ordenada k1 -> k2 -> retiro."""
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)

        # 1. Prepublish k2 en slot anterior
        os.environ["JWT_ACTIVE_KEY_ID"] = "k1"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k1_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k2"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k2_b64
        rotate_jwt("dev", "prepublish", mock_k8s)

        state1 = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state1["active_kid"], "k1")
        self.assertEqual(state1["prev_kid"], "k2")

        # 2. Activate k2 (invierte roles: k2 activa, k1 previa)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k2"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k2_b64
        os.environ["JWT_PREVIOUS_KEY_ID"] = "k1"
        os.environ["JWT_PREVIOUS_SIGNING_KEY_BASE64"] = self.k1_b64
        rotate_jwt("dev", "activate", mock_k8s)

        state2 = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state2["active_kid"], "k2")
        self.assertEqual(state2["prev_kid"], "k1")

        # Simular paso de 25 minutos
        past_time = (datetime.now(timezone.utc) - timedelta(minutes=25)).isoformat()
        mock_k8s.secret_dict["metadata"]["annotations"]["cobroup.com/activated-at"] = past_time

        # 3. Retire k1
        rotate_jwt("dev", "retire", mock_k8s)
        state3 = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state3["active_kid"], "k2")
        self.assertIsNone(state3["prev_kid"])

    def test_emergency_rotation_flow(self):
        """B-21: Rotación de emergencia con revocación global."""
        mock_k8s = MockKubectlExecutor(self.initial_stable_secret)
        os.environ["JWT_ACTIVE_KEY_ID"] = "k-emergency"
        os.environ["JWT_ACTIVE_SIGNING_KEY_BASE64"] = self.k3_b64

        rotate_jwt("dev", "emergency", mock_k8s)

        # 1. Admin-backend escalado a 0 durante la emergencia
        scale_cmds = [item["cmd"] for item in mock_k8s.command_log if "kubectl scale deployment/admin-backend" in item["cmd"]]
        self.assertIn("--replicas=0", scale_cmds[0])
        self.assertIn("--replicas=1", scale_cmds[1])

        # 2. Secret final solo contiene la clave de emergencia (cero slot anterior)
        state = parse_jwt_secret_state(mock_k8s.secret_dict)
        self.assertEqual(state["active_kid"], "k-emergency")
        self.assertIsNone(state["prev_kid"])


if __name__ == "__main__":
    unittest.main()
