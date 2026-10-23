#!/usr/bin/env python3
"""
render_manifests.py - Renderiza y valida de manera segura y reproducible
los manifiestos de Kubernetes de COBROUP para dev, qa y prod.

Decisión de Seguridad JWT (2026-10-22 - DECISION_AUTENTICACION_JWT.md):
- Algoritmo exclusivo: HS256 con secreto simétrico independiente por ambiente.
- Secreto CSPRNG de mínimo 32 bytes (256 bits) transportado en Base64.
- Inyección exclusiva en admin-backend y backend mediante Kubernetes Secrets.
- Frontends completamente aislados del secreto criptográfico.
- Prohibición estricta de RSA, PEM, JWKS, proveedores efímeros y acknowledge flags.

Requisitos: PyYAML (declarado en scripts/requirements.txt)
Uso: python render_manifests.py --env [dev|qa|prod] [--base-dir .] [--render-only]
"""

import argparse
import base64
import os
import shutil
import subprocess
import sys

try:
    import yaml
except ImportError:
    sys.exit(
        "ERROR CRITICO: El paquete 'PyYAML' no está instalado en el entorno Python.\n"
        "Instale las dependencias declaradas ejecutando:\n"
        "  python -m pip install -r scripts/requirements.txt"
    )

ENV_CONFIGS = {
    "dev": {
        "prefix": "DEV_",
        "pvc_storage": "1Gi",
        "pvc_modes": ["ReadWriteOnce", "ReadWriteMany"],
        "required_mode": "ReadWriteOnce",
    },
    "qa": {
        "prefix": "QA_",
        "pvc_storage": "5Gi",
        "pvc_modes": ["ReadWriteOnce", "ReadWriteMany"],
        "required_mode": "ReadWriteOnce",
    },
    "prod": {
        "prefix": "PROD_",
        "pvc_storage": "10Gi",
        "pvc_modes": ["ReadWriteMany"],
        "required_mode": "ReadWriteMany",
    },
}

FORBIDDEN_LEGACY_PATTERNS = [
    "PrivateKeyPem",
    "PublicKeyPem",
    "EphemeralRsa",
    "PersistentRsa",
    "JwksUri",
    "JwksUrl",
    "AllowEphemeralSigning",
    "AcknowledgeNonProductionEphemeralRiskOutsideDevelopment",
    "Jwt__SigningProvider",
    "SigningProvider",
]

PLACEHOLDER_MARKERS = [
    "CHANGE_ME",
    "${{",
    "PLACEHOLDER",
    "DUMMY",
    "TODO",
    "YOUR_KEY",
]


def validate_base64_secret(env: str, secret_name: str, value: str) -> bytes:
    """Valida que el secreto JWT cumpla con el estándar criptográfico CSPRNG Base64 >= 32 bytes."""
    if not value or not value.strip():
        sys.exit(f"ERROR: El secreto '{secret_name}' para el ambiente '{env}' está vacío o ausente.")

    stripped = value.strip()
    upper_val = stripped.upper()
    for marker in PLACEHOLDER_MARKERS:
        if marker in upper_val:
            sys.exit(
                f"ERROR: El secreto '{secret_name}' para el ambiente '{env}' contiene un placeholder o marcador inválido ('{marker}')."
            )

    try:
        raw_bytes = base64.b64decode(stripped, validate=True)
    except Exception as e:
        sys.exit(
            f"ERROR: El secreto '{secret_name}' para el ambiente '{env}' no es una cadena Base64 válida: {e}"
        )

    if len(raw_bytes) < 32:
        sys.exit(
            f"ERROR CRIPTO: El secreto '{secret_name}' para '{env}' decodifica a {len(raw_bytes)} bytes. "
            f"Se requieren mínimo 32 bytes (256 bits) para HMAC-SHA256."
        )

    return raw_bytes


def detect_cross_environment_key_reuse() -> None:
    """Verifica que ningún ambiente comparta el mismo secreto JWT cuando múltiples variables están presentes."""
    env_keys = {
        "dev": os.environ.get("DEV_JWT_SIGNING_KEY_BASE64", "").strip(),
        "qa": os.environ.get("QA_JWT_SIGNING_KEY_BASE64", "").strip(),
        "prod": os.environ.get("PROD_JWT_SIGNING_KEY_BASE64", "").strip(),
    }

    env_names = list(env_keys.keys())
    for i in range(len(env_names)):
        for j in range(i + 1, len(env_names)):
            env_a, env_b = env_names[i], env_names[j]
            key_a, key_b = env_keys[env_a], env_keys[env_b]
            if key_a and key_b and key_a == key_b:
                sys.exit(
                    f"ERROR CRITICO DE SEGURIDAD: Reutilización de clave detectada entre ambientes: "
                    f"'{env_a}' y '{env_b}' tienen exactamente el mismo valor de secreto JWT. "
                    f"Cada ambiente DEBE disponer de una clave CSPRNG independiente."
                )


def render_manifests(env: str, base_dir: str = ".", render_only: bool = False) -> None:
    if env not in ENV_CONFIGS:
        sys.exit(f"ERROR: Ambiente desconocido '{env}'. Valores válidos: dev, qa, prod.")

    cfg = ENV_CONFIGS[env]
    prefix = cfg["prefix"]
    env_dir = os.path.join(base_dir, env)

    if not os.path.isdir(env_dir):
        sys.exit(f"ERROR: No se encontró el directorio de manifiestos: {env_dir}")

    # 1. Validar variables requeridas de entorno
    ops_db = os.environ.get(f"{prefix}OPERATIONSDATABASE_CONNECTIONSTRING", "").strip()
    ident_db = os.environ.get(f"{prefix}IDENTITYDATABASE_CONNECTIONSTRING", "").strip()
    jwt_key = os.environ.get(f"{prefix}JWT_SIGNING_KEY_BASE64", "").strip()

    missing_vars = []
    if not ops_db:
        missing_vars.append(f"{prefix}OPERATIONSDATABASE_CONNECTIONSTRING")
    if not ident_db:
        missing_vars.append(f"{prefix}IDENTITYDATABASE_CONNECTIONSTRING")
    if not jwt_key:
        missing_vars.append(f"{prefix}JWT_SIGNING_KEY_BASE64")

    if missing_vars:
        sys.exit(f"ERROR: Faltan variables requeridas para el ambiente '{env}': {', '.join(missing_vars)}")

    # Validar formato y longitud criptográfica de la clave JWT
    validate_base64_secret(env, f"{prefix}JWT_SIGNING_KEY_BASE64", jwt_key)

    # Detectar reutilización cruzada de claves entre ambientes
    detect_cross_environment_key_reuse()

    # 2. Mapa de sustitución exacta para placeholders ${{...}}
    p_open = "${" + "{"
    p_close = "}}"
    title_prefix = prefix.capitalize()  # "Dev_", "Qa_", "Prod_"

    replacements = {
        f"{p_open}{title_prefix}OperationsDatabase__ConnectionString{p_close}": ops_db,
        f"{p_open}{title_prefix}IdentityDatabase__ConnectionString{p_close}": ident_db,
        f"{p_open}{title_prefix}Jwt__SigningKeyBase64{p_close}": jwt_key,
    }

    ghcr_user = os.environ.get("GHCR_USERNAME", "").strip()
    ghcr_token = os.environ.get("GHCR_TOKEN", "").strip()

    # 3. Escanear y sustituir en todos los archivos YAML del ambiente
    substituted_files = []
    all_yaml_files = []

    for root, _, files in os.walk(env_dir):
        for file in files:
            if file.endswith((".yaml", ".yml")):
                filepath = os.path.join(root, file)
                all_yaml_files.append(filepath)

                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                modified = content
                for placeholder, val in replacements.items():
                    if placeholder in modified:
                        modified = modified.replace(placeholder, val)
                        placeholder_name = placeholder.strip("${}")
                        # Sanitize logging: NEVER log secret values
                        if "Jwt" in placeholder_name or "Secret" in placeholder_name or "Key" in placeholder_name:
                            print(f"[OK] Sustituido '{placeholder_name}' (redactado) en {os.path.relpath(filepath, base_dir)}")
                        else:
                            print(f"[OK] Sustituido '{placeholder_name}' en {os.path.relpath(filepath, base_dir)}")

                if file == "ghcr-secret.yaml" and ghcr_user and ghcr_token:
                    auth_b64 = base64.b64encode(f"{ghcr_user}:{ghcr_token}".encode("utf-8")).decode("utf-8")
                    modified = modified.replace("CHANGE_ME_GITHUB_USER", ghcr_user)
                    modified = modified.replace("CHANGE_ME_GITHUB_PAT", ghcr_token)
                    modified = modified.replace("CHANGE_ME", auth_b64)
                    print(f"[OK] Inyectadas credenciales GHCR en {os.path.relpath(filepath, base_dir)}")

                if modified != content:
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(modified)
                    substituted_files.append(filepath)

    # 4. Validar ausencia de placeholders no resueltos y rechazo estricto de términos RSA/JWKS/PEM/Acknowledge
    unresolved = []
    for filepath in all_yaml_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        if p_open in content:
            unresolved.append(f"{os.path.relpath(filepath, base_dir)} (placeholders sin resolver)")
        for forbidden in FORBIDDEN_LEGACY_PATTERNS:
            if forbidden in content:
                unresolved.append(f"{os.path.relpath(filepath, base_dir)} (residuo no permitido: {forbidden})")
        if "CHANGE_ME" in content and not (ghcr_user and ghcr_token):
            unresolved.append(f"{os.path.relpath(filepath, base_dir)} (credenciales GHCR pendientes)")

        # Validar aislamiento de Frontend: NINGUN frontend debe contener la clave JWT
        rel_path = os.path.relpath(filepath, base_dir).replace("\\", "/")
        if "frontend" in rel_path and not "admin-backend" in rel_path and not "backend" in rel_path:
            if "Jwt__SigningKeyBase64" in content or (jwt_key and jwt_key in content):
                unresolved.append(f"{rel_path} (VIOLACION CRITICA: la clave JWT no debe inyectarse en frontends)")

    if unresolved:
        sys.exit(f"ERROR: Placeholders o residuos pendientes de saneamiento en:\n  - " + "\n  - ".join(unresolved))

    # 5. Validar sintaxis YAML estricta de todos los archivos del ambiente
    for filepath in all_yaml_files:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                docs = list(yaml.safe_load_all(f))
            print(f"[OK] Sintaxis YAML válida: {os.path.relpath(filepath, base_dir)} ({len(docs)} documentos)")
        except Exception as e:
            sys.exit(f"ERROR: Sintaxis YAML inválida en {os.path.relpath(filepath, base_dir)}: {e}")

    # 6. Validar estructura Kubernetes y requerimientos B-09 de almacenamiento durable
    backend_manifest = os.path.join(env_dir, "backend", "backend-manifest.yaml")
    if not os.path.isfile(backend_manifest):
        sys.exit(f"ERROR: Falta el manifiesto operativo {backend_manifest}")

    with open(backend_manifest, "r", encoding="utf-8") as f:
        docs = list(yaml.safe_load_all(f))

    pvc_found = False
    mount_found = False
    volume_found = False
    storage_provider_ok = False
    evidence_path_ok = False
    backend_active_kid_ok = False

    for doc in docs:
        if not doc:
            continue
        kind = doc.get("kind")
        meta = doc.get("metadata", {})
        name = meta.get("name")

        if kind == "PersistentVolumeClaim" and name == "backend-evidence-pvc":
            pvc_found = True
            spec = doc.get("spec", {})
            modes = spec.get("accessModes", [])
            req_mode = cfg["required_mode"]
            if req_mode not in modes:
                sys.exit(
                    f"ERROR en {env}: PVC 'backend-evidence-pvc' debe incluir modo de acceso '{req_mode}', "
                    f"pero tiene: {modes}."
                )
            print(f"[OK] Verificado PersistentVolumeClaim 'backend-evidence-pvc' con modo '{req_mode}'.")

        elif kind == "Deployment" and name == "backend":
            spec = doc.get("spec", {}).get("template", {}).get("spec", {})
            for vol in spec.get("volumes", []):
                if vol.get("name") == "backend-evidence-volume":
                    pvc_ref = vol.get("persistentVolumeClaim", {}).get("claimName")
                    if pvc_ref == "backend-evidence-pvc":
                        volume_found = True

            for container in spec.get("containers", []):
                if container.get("name") == "backend":
                    for mount in container.get("volumeMounts", []):
                        if mount.get("name") == "backend-evidence-volume" and mount.get("mountPath") == "/var/cobroup/evidences":
                            mount_found = True

        elif kind == "ConfigMap" and name == "backend-config":
            data = doc.get("data", {})
            if data.get("Storage__Provider") == "FileSystem":
                storage_provider_ok = True
            if data.get("Storage__EvidencePath") == "/var/cobroup/evidences":
                evidence_path_ok = True
            if data.get("Jwt__ActiveKeyId"):
                backend_active_kid_ok = True

    if not pvc_found:
        sys.exit(f"ERROR: PersistentVolumeClaim 'backend-evidence-pvc' no encontrado en {backend_manifest}")
    if not volume_found:
        sys.exit(f"ERROR: Volume 'backend-evidence-volume' no encontrado en el Deployment backend")
    if not mount_found:
        sys.exit(f"ERROR: VolumeMount '/var/cobroup/evidences' no encontrado en el contenedor backend")
    if not (storage_provider_ok and evidence_path_ok):
        sys.exit(f"ERROR: ConfigMap 'backend-config' no configura Storage__Provider o Storage__EvidencePath correctamente")
    if not backend_active_kid_ok:
        sys.exit(f"ERROR: ConfigMap 'backend-config' no configura 'Jwt__ActiveKeyId'")

    print("[OK] Verificación de almacenamiento durable completada exitosamente.")

    # 7. Validar configuración simétrica HS256 de BackendAdmin
    admin_backend_manifest = os.path.join(env_dir, "admin-backend", "admin-backend-manifest.yaml")
    if not os.path.isfile(admin_backend_manifest):
        sys.exit(f"ERROR: Falta el manifiesto de administración {admin_backend_manifest}")

    with open(admin_backend_manifest, "r", encoding="utf-8") as f:
        admin_docs = list(yaml.safe_load_all(f))

    admin_active_kid_ok = False
    admin_deployment = None

    for doc in admin_docs:
        if not doc:
            continue
        if doc.get("kind") == "ConfigMap" and doc.get("metadata", {}).get("name") == "admin-backend-config":
            data = doc.get("data", {})
            if data.get("Jwt__ActiveKeyId"):
                admin_active_kid_ok = True
        elif doc.get("kind") == "Deployment" and doc.get("metadata", {}).get("name") == "admin-backend":
            admin_deployment = doc

    if not admin_active_kid_ok:
        sys.exit(f"ERROR: ConfigMap 'admin-backend-config' debe especificar 'Jwt__ActiveKeyId'.")
    if not admin_deployment:
        sys.exit(f"ERROR: Deployment 'admin-backend' no encontrado en {admin_backend_manifest}")

    # Verificar que el secreto admin-backend-secret y backend-secret contengan Jwt__SigningKeyBase64
    for svc_name in ["admin-backend", "backend"]:
        sec_path = os.path.join(env_dir, svc_name, "secret.yaml")
        with open(sec_path, "r", encoding="utf-8") as f:
            sec_doc = yaml.safe_load(f)
        str_data = sec_doc.get("stringData", {})
        if "Jwt__SigningKeyBase64" not in str_data or not str_data["Jwt__SigningKeyBase64"]:
            sys.exit(f"ERROR: {svc_name}/secret.yaml no contiene 'Jwt__SigningKeyBase64' resuelto.")

    print(f"[OK] Verificada configuración simétrica HS256 consistente para admin-backend y backend en '{env}'.")

    # 8. Validar con kubectl kustomize si la herramienta está disponible
    kubectl_bin = shutil.which("kubectl")
    if kubectl_bin:
        res = subprocess.run([kubectl_bin, "kustomize", env_dir], capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR: 'kubectl kustomize {env_dir}' falló:\n{res.stderr}")
        print(f"[OK] 'kubectl kustomize {env_dir}' ejecutado y validado exitosamente.")
    else:
        print("[INFO] 'kubectl' no encontrado en PATH. Omisión de renderizado kustomize local.")

    print(f"\nRenderizado y validación de manifiestos para '{env}' completado con éxito (HS256 per-environment).")


def main():
    parser = argparse.ArgumentParser(description="Renderiza y valida manifiestos de Kubernetes para COBROUP.")
    parser.add_argument("--env", required=True, choices=["dev", "qa", "prod"], help="Ambiente objetivo.")
    parser.add_argument("--base-dir", default=".", help="Directorio raíz del repositorio de ambientes.")
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="Modo render-only.",
    )
    args = parser.parse_args()

    render_manifests(args.env, args.base_dir, render_only=args.render_only)


if __name__ == "__main__":
    main()
