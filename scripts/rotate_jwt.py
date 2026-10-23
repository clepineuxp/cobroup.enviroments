#!/usr/bin/env python3
"""
rotate_jwt.py - Orquestador operacional, coordinado y recuperable de rotación HS256 (B-21 y B-23).

Implementa la máquina de estados estricta para rotación de claves JWT HS256:
- prepublish: publica nueva clave en slot anterior sin alterar emisión.
- activate: convierte la clave anterior en activa e invierte los roles.
- retire: revoca refresh tokens del kid anterior y retira la clave (bloqueo >= 20 min).
- emergency: escala admin a 0, revoca todos los refresh tokens, aplica nueva clave única y restablece.

Garantías:
1. Un único Kubernetes Secret ('jwt-signing-secret') para identificadores y material.
2. Cero persistencia de claves o YAML sensible en disco.
3. Orden de rollout estricto: Backend (180s) -> Admin-Backend (180s).
4. Rollback verificado en memoria ante fallo.
5. Verificación estricta de host SSH con pinning ED25519 antes de cualquier conexión.
6. Registro exclusivo de metadatos no sensibles (acción, kid, conteo, timestamp, resultado).
"""

import argparse
import base64
from datetime import datetime, timezone
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

try:
    import yaml
except ImportError:
    sys.exit("ERROR: Se requiere PyYAML. Ejecute 'pip install pyyaml'.")

KEY_ID_REGEX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
MIN_RETIRE_SECONDS = 1200  # 20 minutos (15m token TTL + 30s clock skew + buffer conservador)


class KubectlExecutor:
    """Ejecutor de comandos kubectl en clúster local o remoto vía SSH verificado."""

    def __init__(
        self,
        ssh_host: str | None = None,
        ssh_user: str | None = None,
        ssh_port: int = 22,
        ssh_key: str | None = None,
        ssh_fingerprint: str | None = None,
        tmp_dir: str | None = None,
    ):
        self.ssh_host = ssh_host
        self.ssh_user = ssh_user
        self.ssh_port = ssh_port
        self.ssh_key = ssh_key
        self.ssh_fingerprint = ssh_fingerprint
        self.tmp_dir = tmp_dir
        self.known_hosts_path = None
        self.deploy_key_path = None

        if self.ssh_host:
            self._setup_ssh()

    def _setup_ssh(self) -> None:
        if not self.ssh_user or not self.ssh_key or not self.ssh_fingerprint:
            sys.exit("ERROR B-23: Conexión remota requiere SSH_USER, SSH_KEY y SSH_HOST_ED25519_FINGERPRINT.")

        if not self.tmp_dir:
            self.tmp_dir = tempfile.mkdtemp()
            try:
                os.chmod(self.tmp_dir, 0o700)
            except Exception:
                pass

        self.deploy_key_path = os.path.join(self.tmp_dir, "deploy_key")
        with open(self.deploy_key_path, "w", encoding="utf-8") as f:
            f.write(self.ssh_key.strip() + "\n")
        try:
            os.chmod(self.deploy_key_path, 0o600)
        except Exception:
            pass

        self.known_hosts_path = os.path.join(self.tmp_dir, "known_hosts")

        # Ejecutar verify_ssh_host
        scripts_dir = os.path.dirname(os.path.abspath(__file__))
        verify_script = os.path.join(scripts_dir, "verify_ssh_host.py")
        cmd = [
            sys.executable,
            verify_script,
            "--host",
            self.ssh_host,
            "--port",
            str(self.ssh_port),
            "--expected-fingerprint",
            self.ssh_fingerprint,
            "--out-known-hosts",
            self.known_hosts_path,
        ]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR B-23: Falló la verificación de autenticidad del host SSH:\n{res.stderr.strip()}")

    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        """Ejecuta un comando y retorna (returncode, stdout, stderr)."""
        if self.ssh_host:
            ssh_bin = shutil.which("ssh") or "ssh"
            ssh_cmd = [
                ssh_bin,
                "-T",
                "-p",
                str(self.ssh_port),
                "-i",
                self.deploy_key_path,
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                f"UserKnownHostsFile={self.known_hosts_path}",
                "-o",
                "BatchMode=yes",
                f"{self.ssh_user}@{self.ssh_host}",
                cmd_str,
            ]
            res = subprocess.run(ssh_cmd, input=stdin_data, capture_output=True, text=True)
            return res.returncode, res.stdout, res.stderr
        else:
            res = subprocess.run(cmd_str, input=stdin_data, capture_output=True, text=True, shell=True)
            return res.returncode, res.stdout, res.stderr

    def cleanup(self) -> None:
        if self.tmp_dir and os.path.isdir(self.tmp_dir):
            try:
                shutil.rmtree(self.tmp_dir, ignore_errors=True)
            except Exception:
                pass


def validate_key_id(name: str, kid: str) -> str:
    stripped = (kid or "").strip()
    if not stripped or not KEY_ID_REGEX.match(stripped):
        sys.exit(f"ERROR: Identificador '{name}' ('{stripped}') inválido. Requiere formato '^[A-Za-z0-9._-]{{1,64}}$'.")
    return stripped


def validate_base64_secret(name: str, val: str) -> bytes:
    stripped = (val or "").strip()
    if not stripped:
        sys.exit(f"ERROR: Secreto '{name}' no puede estar vacío.")
    try:
        raw = base64.b64decode(stripped, validate=True)
    except Exception as e:
        sys.exit(f"ERROR: Secreto '{name}' no es Base64 válido: {e}")
    if len(raw) < 32:
        sys.exit(f"ERROR: Secreto '{name}' decodifica a {len(raw)} bytes; se requieren mínimo 32 bytes CSPRNG.")
    return raw


def get_cluster_jwt_secret(k8s: KubectlExecutor, namespace: str) -> dict | None:
    code, stdout, stderr = k8s.run_cmd(f"kubectl get secret jwt-signing-secret -n {namespace} -o json")
    if code != 0:
        if "NotFound" in stderr or "not found" in stderr.lower():
            return None
        sys.exit(f"ERROR: No se pudo obtener 'jwt-signing-secret' del namespace '{namespace}': {stderr.strip()}")
    try:
        return json.loads(stdout)
    except Exception as e:
        sys.exit(f"ERROR: Falló al parsear el JSON de 'jwt-signing-secret': {e}")


def parse_jwt_secret_state(secret_dict: dict | None) -> dict:
    if not secret_dict:
        return {
            "exists": False,
            "active_kid": None,
            "active_b64": None,
            "prev_kid": None,
            "prev_b64": None,
            "activated_at": None,
            "raw_dict": None,
        }

    data = secret_dict.get("data", {})
    annotations = secret_dict.get("metadata", {}).get("annotations", {})

    active_kid = None
    if "Jwt__ActiveKeyId" in data:
        try:
            active_kid = base64.b64decode(data["Jwt__ActiveKeyId"]).decode("utf-8").strip()
        except Exception:
            pass

    active_b64 = None
    if "Jwt__SigningKeyBase64" in data:
        try:
            active_b64 = base64.b64decode(data["Jwt__SigningKeyBase64"]).decode("utf-8").strip()
        except Exception:
            pass

    prev_kid = None
    if "Jwt__PreviousValidationKeys__0__KeyId" in data:
        try:
            prev_kid = base64.b64decode(data["Jwt__PreviousValidationKeys__0__KeyId"]).decode("utf-8").strip()
        except Exception:
            pass

    prev_b64 = None
    if "Jwt__PreviousValidationKeys__0__SigningKeyBase64" in data:
        try:
            prev_b64 = base64.b64decode(data["Jwt__PreviousValidationKeys__0__SigningKeyBase64"]).decode("utf-8").strip()
        except Exception:
            pass

    activated_at = annotations.get("cobroup.com/activated-at")

    return {
        "exists": True,
        "active_kid": active_kid,
        "active_b64": active_b64,
        "prev_kid": prev_kid,
        "prev_b64": prev_b64,
        "activated_at": activated_at,
        "raw_dict": secret_dict,
    }


def build_jwt_secret_yaml(
    env: str,
    namespace: str,
    active_kid: str,
    active_b64: str,
    prev_kid: str | None = None,
    prev_b64: str | None = None,
    activated_at: str | None = None,
) -> str:
    jwt_data = {
        "Jwt__ActiveKeyId": base64.b64encode(active_kid.encode("utf-8")).decode("utf-8"),
        "Jwt__SigningKeyBase64": base64.b64encode(active_b64.encode("utf-8")).decode("utf-8"),
    }
    if prev_kid and prev_b64:
        jwt_data["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(prev_kid.encode("utf-8")).decode("utf-8")
        jwt_data["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(
            prev_b64.encode("utf-8")
        ).decode("utf-8")

    annotations = {}
    if activated_at:
        annotations["cobroup.com/activated-at"] = activated_at

    doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "jwt-signing-secret",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "cobroup",
                "environment": env,
            },
            "annotations": annotations,
        },
        "type": "Opaque",
        "data": jwt_data,
    }
    return yaml.safe_dump(doc, sort_keys=False)


def perform_safe_rollout_and_verify(
    k8s: KubectlExecutor,
    namespace: str,
    new_secret_yaml: str,
    original_secret_dict: dict | None,
) -> None:
    """
    Aplica el nuevo Secret y reinicia las cargas en orden seguro:
    1. Aplica Secret en memoria.
    2. Reinicia y espera deployment/backend (180s).
       Si falla: revierte Secret en memoria, reinicia backend y aborta. NO toca admin-backend.
    3. Reinicia y espera deployment/admin-backend (180s).
       Si falla: revierte Secret en memoria, recupera ambos deployments y aborta.

    Garantías B-21:
    - Si el rollback del Secret falla, se emite ERROR CRITICO con instrucciones manuales.
    - Nunca se ignoran códigos de retorno de kubectl apply, rollout, scale ni rollout status.
    - Nunca se usa except Exception: pass.
    """
    print("==> [Rollout 1/3] Aplicando nuevo 'jwt-signing-secret' en memoria vía stdin...")
    code, _out, stderr = k8s.run_cmd(f"kubectl apply -f - -n {namespace}", stdin_data=new_secret_yaml)
    if code != 0:
        sys.exit(f"ERROR: Falló al aplicar el Secret 'jwt-signing-secret': {stderr.strip()}")

    print("==> [Rollout 2/3] Reiniciando deployment/backend (validador) y esperando estado...")
    code, _out, stderr = k8s.run_cmd(
        f"kubectl rollout restart deployment/backend -n {namespace} && "
        f"kubectl rollout status deployment/backend -n {namespace} --timeout=180s"
    )
    if code != 0:
        print(f"ERROR: Falló el rollout de deployment/backend:\n{stderr.strip()}", file=sys.stderr)
        print("==> INICIANDO ROLLBACK SEGURO: Restaurando Secret previo en memoria...", file=sys.stderr)
        if original_secret_dict:
            orig_yaml = yaml.safe_dump(original_secret_dict)
            rb_secret_code, _rb_out, rb_secret_err = k8s.run_cmd(
                f"kubectl apply -f - -n {namespace}", stdin_data=orig_yaml
            )
            if rb_secret_code != 0:
                print(
                    f"ERROR CRITICO: Falló el rollback del Secret 'jwt-signing-secret'.\n"
                    f"ACCIÓN MANUAL REQUERIDA: Restaurar el Secret manualmente.\n"
                    f"Detalle: {rb_secret_err.strip()}",
                    file=sys.stderr,
                )
            rb_backend_code, _rb_out, rb_backend_err = k8s.run_cmd(
                f"kubectl rollout restart deployment/backend -n {namespace} && "
                f"kubectl rollout status deployment/backend -n {namespace} --timeout=180s"
            )
            if rb_backend_code != 0:
                print(
                    f"ERROR CRITICO: Falló el rollback de deployment/backend.\n"
                    f"ACCIÓN MANUAL REQUERIDA: kubectl rollout restart deployment/backend -n {namespace}\n"
                    f"Detalle: {rb_backend_err.strip()}",
                    file=sys.stderr,
                )
            if rb_secret_code != 0 or rb_backend_code != 0:
                sys.exit("ERROR CRITICO: Rollout de Backend falló Y la recuperación de rollback también falló. Se requiere intervención manual inmediata.")
        sys.exit("ERROR: Rollout de Backend falló. Rollback ejecutado. Admin-backend no fue reiniciado.")

    print("==> [Rollout 3/3] Reiniciando deployment/admin-backend (emisor) y esperando estado...")
    code, _out, stderr = k8s.run_cmd(
        f"kubectl rollout restart deployment/admin-backend -n {namespace} && "
        f"kubectl rollout status deployment/admin-backend -n {namespace} --timeout=180s"
    )
    if code != 0:
        print(f"ERROR: Falló el rollout de deployment/admin-backend:\n{stderr.strip()}", file=sys.stderr)
        print("==> INICIANDO ROLLBACK TOTAL: Restaurando Secret previo y recuperando ambos deployments...", file=sys.stderr)
        if original_secret_dict:
            orig_yaml = yaml.safe_dump(original_secret_dict)
            rb_secret_code, _rb_out, rb_secret_err = k8s.run_cmd(
                f"kubectl apply -f - -n {namespace}", stdin_data=orig_yaml
            )
            if rb_secret_code != 0:
                print(
                    f"ERROR CRITICO: Falló el rollback del Secret 'jwt-signing-secret' en rollback total.\n"
                    f"ACCIÓN MANUAL REQUERIDA: Restaurar el Secret manualmente.\n"
                    f"Detalle: {rb_secret_err.strip()}",
                    file=sys.stderr,
                )
            rb_backend_code, _rb_out, rb_backend_err = k8s.run_cmd(
                f"kubectl rollout restart deployment/backend -n {namespace} && "
                f"kubectl rollout status deployment/backend -n {namespace} --timeout=180s"
            )
            if rb_backend_code != 0:
                print(
                    f"ERROR CRITICO: Falló el rollback de deployment/backend en rollback total.\n"
                    f"ACCIÓN MANUAL REQUERIDA: kubectl rollout restart deployment/backend -n {namespace}\n"
                    f"Detalle: {rb_backend_err.strip()}",
                    file=sys.stderr,
                )
            rb_admin_code, _rb_out, rb_admin_err = k8s.run_cmd(
                f"kubectl rollout restart deployment/admin-backend -n {namespace} && "
                f"kubectl rollout status deployment/admin-backend -n {namespace} --timeout=180s"
            )
            if rb_admin_code != 0:
                print(
                    f"ERROR CRITICO: Falló el rollback de deployment/admin-backend en rollback total.\n"
                    f"ACCIÓN MANUAL REQUERIDA: kubectl rollout restart deployment/admin-backend -n {namespace}\n"
                    f"Detalle: {rb_admin_err.strip()}",
                    file=sys.stderr,
                )
            if rb_secret_code != 0 or rb_backend_code != 0 or rb_admin_code != 0:
                sys.exit("ERROR CRITICO: Rollout de Admin-Backend falló Y la recuperación de rollback también falló. Se requiere intervención manual inmediata.")
        sys.exit("ERROR: Rollout de Admin-Backend falló. Rollback total completado.")


def execute_revocation_job(k8s: KubectlExecutor, namespace: str, arg: str, kid: str | None = None) -> int:
    """
    Ejecuta un Kubernetes Job temporal para invocar de forma operacional
    la revocación de refresh tokens usando el contenedor de admin-backend.

    Garantías B-21:
    - No expone endpoints HTTP ni credenciales en argumentos de línea de comandos.
    - Monta explícitamente 'jwt-signing-secret' para que SymmetricKeyService resuelva
      Jwt__SigningKeyBase64 y Jwt__ActiveKeyId durante la revocación.
    - backoffLimit=0 y restartPolicy=Never para ejecución única y atómica.
    - activeDeadlineSeconds limita la ventana de ejecución total del Job.
    - Recursos mínimos declarados para garantizar scheduling.
    - El kid se pasa exclusivamente por variable de entorno cuando aplica,
      nunca como argumento de línea de comandos.
    """
    # Obtener imagen actual de admin-backend
    code, stdout, stderr = k8s.run_cmd(
        f"kubectl get deployment admin-backend -n {namespace} -o jsonpath='{{.spec.template.spec.containers[0].image}}'"
    )
    if code != 0 or not stdout.strip():
        admin_image = f"ghcr.io/clepineuxp/ms-cobroup-backendadmin:{namespace.replace('cobroup-', '')}"
    else:
        admin_image = stdout.strip()

    job_name = f"jwt-revocation-{int(datetime.now(timezone.utc).timestamp())}"

    # El kid a revocar se inyecta como variable de entorno para evitar exposición en argumentos
    job_cmd = ["dotnet", "MS.Cobroup.BackendAdmin.Api.dll", arg]
    env_vars = []
    if kid:
        env_vars.append({"name": "JWT_REVOKE_KID", "value": kid})

    job_manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": job_name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "jwt-revocation-job",
                "app.kubernetes.io/part-of": "cobroup",
            },
        },
        "spec": {
            "ttlSecondsAfterFinished": 60,
            "backoffLimit": 0,
            "activeDeadlineSeconds": 90,  # Límite total del Job (wait 60s + overhead)
            "template": {
                "spec": {
                    "restartPolicy": "Never",
                    "imagePullSecrets": [{"name": "ghcr-secret"}],
                    "securityContext": {
                        "runAsNonRoot": True,
                        "runAsUser": 1000,
                        "fsGroup": 1000,
                    },
                    "containers": [
                        {
                            "name": "revoker",
                            "image": admin_image,
                            "command": job_cmd,
                            # Fuentes de configuración no sensible
                            "envFrom": [
                                {"configMapRef": {"name": "admin-backend-config"}},
                                # Secret de la aplicación (cadenas de conexión, etc.)
                                {"secretRef": {"name": "admin-backend-secret"}},
                                # Montaje explícito obligatorio de jwt-signing-secret (B-21)
                                {"secretRef": {"name": "jwt-signing-secret"}},
                            ],
                            # Montaje explícito del Secret JWT para que SymmetricKeyService
                            # resuelva Jwt__SigningKeyBase64 y Jwt__ActiveKeyId.
                            # Es obligatorio porque el Job no hereda el envFrom del Deployment.
                            "env": [
                                {
                                    "name": "Jwt__SigningKeyBase64",
                                    "valueFrom": {"secretKeyRef": {"name": "jwt-signing-secret", "key": "Jwt__SigningKeyBase64"}},
                                },
                                {
                                    "name": "Jwt__ActiveKeyId",
                                    "valueFrom": {"secretKeyRef": {"name": "jwt-signing-secret", "key": "Jwt__ActiveKeyId"}},
                                },
                            ] + env_vars,
                            "resources": {
                                "requests": {"cpu": "50m", "memory": "128Mi"},
                                "limits": {"cpu": "200m", "memory": "256Mi"},
                            },
                            "securityContext": {
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                }
            },
        },
    }

    job_yaml = yaml.safe_dump(job_manifest)
    print(f"==> [Revocación] Ejecutando Job '{job_name}' con accion='{arg}'...")

    # Aplicar Job
    code, stdout, stderr = k8s.run_cmd(f"kubectl apply -f - -n {namespace}", stdin_data=job_yaml)
    if code != 0:
        sys.exit(f"ERROR: Falló al crear el Job de revocación '{job_name}': {stderr.strip()}")

    # Esperar finalización del Job (60s)
    code, _wait_stdout, wait_stderr = k8s.run_cmd(
        f"kubectl wait --for=condition=complete job/{job_name} -n {namespace} --timeout=60s"
    )

    # Leer logs para obtener conteo no sensible (independiente del resultado del wait)
    log_code, log_stdout, _log_stderr = k8s.run_cmd(f"kubectl logs job/{job_name} -n {namespace}")

    # Limpiar Job (best-effort, no abortar si falla)
    _del_code, _del_out, _del_err = k8s.run_cmd(
        f"kubectl delete job {job_name} -n {namespace} --ignore-not-found=true"
    )

    if code != 0:
        sys.exit(
            f"ERROR: El Job de revocación '{job_name}' falló o excedió el tiempo límite (60s).\n"
            f"Salida del Job: {log_stdout.strip()}\nError del wait: {wait_stderr.strip()}"
        )

    revoked_count = 0
    for line in log_stdout.splitlines():
        line = line.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                parsed = json.loads(line)
                if "RevokedCount" in parsed:
                    revoked_count = int(parsed["RevokedCount"])
                    break
            except (json.JSONDecodeError, ValueError, TypeError):
                # Línea de log no es JSON válido; continuar buscando en el resto
                continue

    return revoked_count


def rotate_jwt(env: str, action: str, k8s: KubectlExecutor) -> None:
    namespace = os.environ.get("KUBERNETES_NAMESPACE", f"cobroup-{env}").strip()
    now_utc = datetime.now(timezone.utc)
    now_iso = now_utc.isoformat()

    # 1. Obtener estado actual del clúster
    current_raw = get_cluster_jwt_secret(k8s, namespace)
    state = parse_jwt_secret_state(current_raw)

    target_active_kid = os.environ.get("JWT_ACTIVE_KEY_ID", "").strip()
    target_active_b64 = os.environ.get("JWT_ACTIVE_SIGNING_KEY_BASE64", "").strip()
    target_prev_kid = os.environ.get("JWT_PREVIOUS_KEY_ID", "").strip()
    target_prev_b64 = os.environ.get("JWT_PREVIOUS_SIGNING_KEY_BASE64", "").strip()

    if action == "prepublish":
        # Precondición: Clúster en estado estable (sin clave anterior)
        if not state["exists"]:
            sys.exit(f"ERROR: El Secret 'jwt-signing-secret' no existe en '{namespace}'. Ejecute el despliegue inicial primero.")
        if state["prev_kid"]:
            sys.exit(
                f"ERROR: El clúster ya tiene una clave en slot anterior ('{state['prev_kid']}'). "
                f"Complete la rotación mediante 'activate' o 'retire' antes de iniciar un nuevo prepublish."
            )

        validate_key_id("JWT_ACTIVE_KEY_ID", target_active_kid)
        validate_base64_secret("JWT_ACTIVE_SIGNING_KEY_BASE64", target_active_b64)
        validate_key_id("JWT_PREVIOUS_KEY_ID", target_prev_kid)
        validate_base64_secret("JWT_PREVIOUS_SIGNING_KEY_BASE64", target_prev_b64)

        if target_active_kid != state["active_kid"]:
            sys.exit(
                f"ERROR: En prepublish, 'JWT_ACTIVE_KEY_ID' ('{target_active_kid}') debe ser idéntico al activo del clúster ('{state['active_kid']}')."
            )
        if target_prev_kid == target_active_kid:
            sys.exit("ERROR: La nueva clave 'JWT_PREVIOUS_KEY_ID' no puede tener el mismo kid que la activa.")
        if target_prev_b64 == target_active_b64:
            sys.exit("ERROR: El material criptográfico de la clave previa no puede ser idéntico al de la activa.")

        new_secret_yaml = build_jwt_secret_yaml(
            env=env,
            namespace=namespace,
            active_kid=target_active_kid,
            active_b64=target_active_b64,
            prev_kid=target_prev_kid,
            prev_b64=target_prev_b64,
        )

        perform_safe_rollout_and_verify(k8s, namespace, new_secret_yaml, state["raw_dict"])
        print(f"[AUDIT] Accion=prepublish, Ambiente={env}, ActiveKid={target_active_kid}, PrepublishedKid={target_prev_kid}, Timestamp={now_iso}, Resultado=EXITO")

    elif action == "activate":
        # Precondición: La clave a activar debe haber sido prepublicada previamente en el clúster
        if not state["exists"] or not state["prev_kid"]:
            sys.exit("ERROR: No se puede activar una nueva clave sin prepublish previo. El clúster no tiene clave en slot anterior.")

        validate_key_id("JWT_ACTIVE_KEY_ID", target_active_kid)
        validate_base64_secret("JWT_ACTIVE_SIGNING_KEY_BASE64", target_active_b64)
        validate_key_id("JWT_PREVIOUS_KEY_ID", target_prev_kid)
        validate_base64_secret("JWT_PREVIOUS_SIGNING_KEY_BASE64", target_prev_b64)

        if target_active_kid != state["prev_kid"]:
            sys.exit(
                f"ERROR: La clave a activar ('{target_active_kid}') debe ser la previamente publicada en el slot anterior del clúster ('{state['prev_kid']}')."
            )
        if target_prev_kid != state["active_kid"]:
            sys.exit(
                f"ERROR: La clave anterior ('{target_prev_kid}') debe ser la que estaba activa en el clúster ('{state['active_kid']}')."
            )

        new_secret_yaml = build_jwt_secret_yaml(
            env=env,
            namespace=namespace,
            active_kid=target_active_kid,
            active_b64=target_active_b64,
            prev_kid=target_prev_kid,
            prev_b64=target_prev_b64,
            activated_at=now_iso,
        )

        perform_safe_rollout_and_verify(k8s, namespace, new_secret_yaml, state["raw_dict"])
        print(f"[AUDIT] Accion=activate, Ambiente={env}, ActiveKid={target_active_kid}, PreviousKid={target_prev_kid}, ActivatedAt={now_iso}, Resultado=EXITO")

    elif action == "retire":
        if not state["exists"] or not state["prev_kid"]:
            sys.exit("ERROR: No hay ninguna clave anterior en el clúster para retirar.")

        # Validar tiempo transcurrido desde activación (mínimo 20 min)
        activated_at_str = state["activated_at"]
        if not activated_at_str:
            sys.exit("ERROR: No se encontró la marca de activación 'cobroup.com/activated-at'. Retiro bloqueado.")

        try:
            activated_dt = datetime.fromisoformat(activated_at_str)
            if activated_dt.tzinfo is None:
                activated_dt = activated_dt.replace(tzinfo=timezone.utc)
        except Exception:
            sys.exit(f"ERROR: Marca de tiempo de activación inválida: '{activated_at_str}'.")

        elapsed_seconds = (now_utc - activated_dt).total_seconds()
        if elapsed_seconds < MIN_RETIRE_SECONDS:
            sys.exit(
                f"ERROR: Retiro prematuro bloqueado. Solo han transcurrido {elapsed_seconds:.0f}s desde la activación "
                f"(se requiere un mínimo de {MIN_RETIRE_SECONDS}s / 20 minutos para garantizar el vencimiento de tokens)."
            )

        kid_to_retire = state["prev_kid"]
        print(f"==> [Retiro] Revocando refresh tokens asociados al kid '{kid_to_retire}'...")
        revoked_count = execute_revocation_job(k8s, namespace, "--revoke-kid", kid_to_retire)
        print(f"==> [Retiro] Refresh tokens revocados atómicamente: {revoked_count}")

        # Aplicar Secret conteniendo únicamente la clave activa (sin clave anterior)
        new_secret_yaml = build_jwt_secret_yaml(
            env=env,
            namespace=namespace,
            active_kid=state["active_kid"],
            active_b64=state["active_b64"],
            prev_kid=None,
            prev_b64=None,
        )

        perform_safe_rollout_and_verify(k8s, namespace, new_secret_yaml, state["raw_dict"])
        print(
            f"[AUDIT] Accion=retire, Ambiente={env}, ActiveKid={state['active_kid']}, RetiredKid={kid_to_retire}, "
            f"RevokedCount={revoked_count}, Timestamp={now_iso}, Resultado=EXITO"
        )
        print(f"\n[INFO] Clave '{kid_to_retire}' retirada con éxito. El operador ya puede eliminar las variables previas en GitHub.")

    elif action == "emergency":
        validate_key_id("JWT_ACTIVE_KEY_ID", target_active_kid)
        validate_base64_secret("JWT_ACTIVE_SIGNING_KEY_BASE64", target_active_b64)

        # PASO 1: Escalar admin-backend a 0 para detener la emisión de tokens ANTES de revocar.
        # Si este paso falla, NO continuamos: emitir tokens mientras revocamos es inconsistente.
        print("==> [Emergencia] Suspendiendo emisión: escalando deployment/admin-backend a 0 réplicas...")
        code, _out, stderr = k8s.run_cmd(
            f"kubectl scale deployment/admin-backend --replicas=0 -n {namespace}"
        )
        if code != 0:
            sys.exit(
                f"ERROR CRITICO [Emergencia]: No se pudo escalar admin-backend a 0 réplicas.\n"
                f"La rotación de emergencia se aborta para evitar emitir y revocar tokens simultáneamente.\n"
                f"Detalle: {stderr.strip()}"
            )

        # Esperar que admin-backend llegue a 0 réplicas antes de revocar
        code, _out, stderr = k8s.run_cmd(
            f"kubectl rollout status deployment/admin-backend -n {namespace} --timeout=60s"
        )
        if code != 0:
            sys.exit(
                "ERROR CRITICO [Emergencia]: Falló la confirmación de escalamiento a 0 réplicas para admin-backend.\n"
                "La rotación de emergencia se aborta inmediatamente para evitar emitir tokens mientras se revoca.\n"
                f"Detalle: {stderr.strip()}"
            )

        # PASO 2: Revocar sesiones (admin-backend está en 0 réplicas, no puede emitir)
        print("==> [Emergencia] Revocando atómicamente todas las familias de refresh tokens activos...")
        revoked_count = execute_revocation_job(k8s, namespace, "--revoke-all")
        print(f"==> [Emergencia] Total de sesiones revocadas: {revoked_count}")

        # PASO 3: Aplicar el nuevo Secret con la clave de emergencia
        print("==> [Emergencia] Aplicando nuevo Secret exclusivamente con la nueva clave activa...")
        new_secret_yaml = build_jwt_secret_yaml(
            env=env,
            namespace=namespace,
            active_kid=target_active_kid,
            active_b64=target_active_b64,
            prev_kid=None,
            prev_b64=None,
        )
        code, _out, stderr = k8s.run_cmd(f"kubectl apply -f - -n {namespace}", stdin_data=new_secret_yaml)
        if code != 0:
            sys.exit(
                f"ERROR CRITICO [Emergencia]: Falló al aplicar el nuevo Secret de emergencia.\n"
                f"Estado del clúster: admin-backend=0 réplicas, sesiones revocadas.\n"
                f"ACCIÓN MANUAL REQUERIDA: Aplicar el Secret manualmente y escalar admin-backend.\n"
                f"Detalle: {stderr.strip()}"
            )

        # PASO 4: Reiniciar Backend (validador) con la nueva clave
        print("==> [Emergencia] Reiniciando y verificando deployment/backend (validador)...")
        code, _out, stderr = k8s.run_cmd(
            f"kubectl rollout restart deployment/backend -n {namespace} && "
            f"kubectl rollout status deployment/backend -n {namespace} --timeout=180s"
        )
        if code != 0:
            sys.exit(
                f"ERROR CRITICO [Emergencia]: Falló el rollout de Backend.\n"
                f"Estado: admin-backend=0 réplicas, sesiones revocadas, Secret actualizado.\n"
                f"ACCIÓN MANUAL REQUERIDA: Escalar admin-backend a réplicas normales y verificar backend.\n"
                f"Detalle: {stderr.strip()}"
            )

        # PASO 5: Restablecer admin-backend con la nueva clave
        print("==> [Emergencia] Restableciendo y reiniciando deployment/admin-backend...")
        code, _out, stderr = k8s.run_cmd(
            f"kubectl scale deployment/admin-backend --replicas=1 -n {namespace} && "
            f"kubectl rollout status deployment/admin-backend -n {namespace} --timeout=180s"
        )
        if code != 0:
            sys.exit(
                f"ERROR CRITICO [Emergencia]: Falló el restablecimiento de admin-backend a 1 réplica.\n"
                f"Estado: backend=OK, admin-backend=0 réplicas.\n"
                f"ACCIÓN MANUAL REQUERIDA: kubectl scale deployment/admin-backend --replicas=1 -n {namespace}\n"
                f"Detalle: {stderr.strip()}"
            )

        print(
            f"[AUDIT] Accion=emergency, Ambiente={env}, NewActiveKid={target_active_kid}, "
            f"RevokedCount={revoked_count}, Timestamp={now_iso}, Resultado=EXITO"
        )
        print("[WARNING] Rotación de emergencia completada. Todas las sesiones activas han sido invalidadas.")


def main():
    parser = argparse.ArgumentParser(description="Orquestador de rotación JWT HS256 para COBROUP (B-21).")
    parser.add_argument("--env", required=True, choices=["dev", "qa", "prod"], help="Ambiente objetivo.")
    parser.add_argument(
        "--action",
        required=True,
        choices=["prepublish", "activate", "retire", "emergency"],
        help="Acción de rotación a ejecutar.",
    )
    args = parser.parse_args()

    # Verificar si se conecta vía SSH o directo
    ssh_host = os.environ.get("SSH_HOST", "").strip()
    ssh_user = os.environ.get("SSH_USER", "").strip()
    ssh_port = int(os.environ.get("SSH_PORT", "22").strip() or "22")
    ssh_key = os.environ.get("SSH_KEY", "").strip()
    ssh_fingerprint = os.environ.get("SSH_HOST_ED25519_FINGERPRINT", "").strip()

    k8s = KubectlExecutor(
        ssh_host=ssh_host or None,
        ssh_user=ssh_user or None,
        ssh_port=ssh_port,
        ssh_key=ssh_key or None,
        ssh_fingerprint=ssh_fingerprint or None,
    )

    try:
        rotate_jwt(args.env, args.action, k8s)
    finally:
        k8s.cleanup()


if __name__ == "__main__":
    main()
