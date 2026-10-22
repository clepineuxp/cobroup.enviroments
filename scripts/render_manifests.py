#!/usr/bin/env python3
"""
render_manifests.py - Renderiza y valida de manera segura y reproducible
los manifiestos de Kubernetes de COBROUP para dev, qa y prod.

Decisión de Seguridad JWT (2026-10-22):
- En Development: Se utiliza EphemeralRsa explícito (en memoria, sin claves PEM externas).
- En QA y Producción: EphemeralRsa está prohibido. Se requiere un proveedor persistente
  (PersistentRsa/KMS), registrado como backlog obligatorio previo a producción.
  El gate de despliegue detiene el pipeline antes de la transferencia SCP.

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
        "allowed_signing_providers": ["EphemeralRsa"],
        "requires_persistent_provider": False,
    },
    "qa": {
        "prefix": "QA_",
        "pvc_storage": "5Gi",
        "pvc_modes": ["ReadWriteOnce", "ReadWriteMany"],
        "required_mode": "ReadWriteOnce",
        "allowed_signing_providers": ["PersistentRsa"],
        "requires_persistent_provider": True,
    },
    "prod": {
        "prefix": "PROD_",
        "pvc_storage": "10Gi",
        "pvc_modes": ["ReadWriteMany"],
        "required_mode": "ReadWriteMany",
        "allowed_signing_providers": ["PersistentRsa"],
        "requires_persistent_provider": True,
    },
}


def render_manifests(env: str, base_dir: str = ".", render_only: bool = False) -> None:
    if env not in ENV_CONFIGS:
        sys.exit(f"ERROR: Ambiente desconocido '{env}'. Valores válidos: dev, qa, prod.")

    cfg = ENV_CONFIGS[env]
    prefix = cfg["prefix"]
    env_dir = os.path.join(base_dir, env)

    if not os.path.isdir(env_dir):
        sys.exit(f"ERROR: No se encontró el directorio de manifiestos: {env_dir}")

    # 1. Validar variables requeridas de base de datos
    ops_db = os.environ.get(f"{prefix}OPERATIONSDATABASE_CONNECTIONSTRING", "").strip()
    ident_db = os.environ.get(f"{prefix}IDENTITYDATABASE_CONNECTIONSTRING", "").strip()

    missing_vars = []
    if not ops_db:
        missing_vars.append(f"{prefix}OPERATIONSDATABASE_CONNECTIONSTRING")
    if not ident_db:
        missing_vars.append(f"{prefix}IDENTITYDATABASE_CONNECTIONSTRING")

    if missing_vars:
        sys.exit(f"ERROR: Faltan variables requeridas para el ambiente '{env}': {', '.join(missing_vars)}")

    # 2. Mapa de sustitución exacta para placeholders ${{...}}
    p_open = "${" + "{"
    p_close = "}}"
    title_prefix = prefix.capitalize()  # "Dev_", "Qa_", "Prod_"

    replacements = {
        f"{p_open}{title_prefix}OperationsDatabase__ConnectionString{p_close}": ops_db,
        f"{p_open}{title_prefix}IdentityDatabase__ConnectionString{p_close}": ident_db,
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

    # 4. Validar ausencia de placeholders no resueltos y que no existan residuos de PEM
    unresolved = []
    for filepath in all_yaml_files:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        if p_open in content:
            unresolved.append(f"{os.path.relpath(filepath, base_dir)} (placeholders sin resolver)")
        if "PrivateKeyPem" in content:
            unresolved.append(f"{os.path.relpath(filepath, base_dir)} (residuo de clave PEM no permitido)")
        if "CHANGE_ME" in content and not (ghcr_user and ghcr_token):
            unresolved.append(f"{os.path.relpath(filepath, base_dir)} (credenciales GHCR pendientes)")

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

    if not pvc_found:
        sys.exit(f"ERROR: PersistentVolumeClaim 'backend-evidence-pvc' no encontrado en {backend_manifest}")
    if not volume_found:
        sys.exit(f"ERROR: Volume 'backend-evidence-volume' no encontrado en el Deployment backend")
    if not mount_found:
        sys.exit(f"ERROR: VolumeMount '/var/cobroup/evidences' no encontrado en el contenedor backend")
    if not (storage_provider_ok and evidence_path_ok):
        sys.exit(f"ERROR: ConfigMap 'backend-config' no configura Storage__Provider o Storage__EvidencePath correctamente")

    print("[OK] Verificación de almacenamiento durable completada exitosamente.")

    # 7. Validar configuración del proveedor de firma JWT de BackendAdmin
    admin_backend_manifest = os.path.join(env_dir, "admin-backend", "admin-backend-manifest.yaml")
    if not os.path.isfile(admin_backend_manifest):
        sys.exit(f"ERROR: Falta el manifiesto de administración {admin_backend_manifest}")

    with open(admin_backend_manifest, "r", encoding="utf-8") as f:
        admin_docs = list(yaml.safe_load_all(f))

    signing_provider = None
    allow_ephemeral = None
    admin_deployment = None

    for doc in admin_docs:
        if not doc:
            continue
        if doc.get("kind") == "ConfigMap" and doc.get("metadata", {}).get("name") == "admin-backend-config":
            data = doc.get("data", {})
            signing_provider = data.get("Jwt__SigningProvider")
            allow_ephemeral = data.get("Jwt__AllowEphemeralSigning")
        elif doc.get("kind") == "Deployment" and doc.get("metadata", {}).get("name") == "admin-backend":
            admin_deployment = doc

    if not signing_provider:
        sys.exit(f"ERROR: ConfigMap 'admin-backend-config' debe especificar 'Jwt__SigningProvider'.")
    if not admin_deployment:
        sys.exit(f"ERROR: Deployment 'admin-backend' no encontrado en {admin_backend_manifest}")

    if env == "dev":
        if signing_provider != "EphemeralRsa" or allow_ephemeral != "true":
            sys.exit(
                f"ERROR en dev: 'Jwt__SigningProvider' debe ser 'EphemeralRsa' y 'Jwt__AllowEphemeralSigning' debe ser 'true'."
            )

        # Validación B-19: Mientras la clave sea efímera, el rollout no debe superponer dos pods emisores incompatibles
        strategy = admin_deployment.get("spec", {}).get("strategy", {})
        strategy_type = strategy.get("type")
        if strategy_type == "RollingUpdate":
            rolling_update = strategy.get("rollingUpdate", {})
            max_surge = rolling_update.get("maxSurge", 1)
            if max_surge != 0:
                sys.exit(
                    "ERROR DE SEGURIDAD (B-19): Con el proveedor 'EphemeralRsa', el Deployment 'admin-backend' "
                    "no puede usar RollingUpdate con maxSurge > 0 porque provocaría la coexistencia de dos pods "
                    "con claves efímeras divergentes y rechazo intermitente de tokens tras el Service.\n"
                    "Configure 'strategy.type: Recreate' o un rollout que impida la superposición de réplicas."
                )
        elif strategy_type != "Recreate":
            sys.exit(
                f"ERROR DE SEGURIDAD (B-19): Con 'EphemeralRsa', la estrategia de despliegue de 'admin-backend' debe ser 'Recreate' "
                f"(configurada actualmente como '{strategy_type}')."
            )

        print("[OK] Verificado modo EphemeralRsa con estrategia 'Recreate' (sin superposición de pods emisores, B-19).")
    else:
        # En QA y Producción: EphemeralRsa está estrictamente prohibido
        if signing_provider == "EphemeralRsa":
            sys.exit(
                f"ERROR DE SEGURIDAD CRITICO en {env}: El proveedor 'EphemeralRsa' está estrictamente prohibido fuera de Development.\n"
                f"Consulte la decisión arquitectónica vigente (DECISION_AUTENTICACION_JWT.md)."
            )

        print(f"[OK] Verificada restricción de firma para {env}: proveedor '{signing_provider}'.")

    # 8. Validar con kubectl kustomize si la herramienta está disponible
    kubectl_bin = shutil.which("kubectl")
    if kubectl_bin:
        res = subprocess.run([kubectl_bin, "kustomize", env_dir], capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR: 'kubectl kustomize {env_dir}' falló:\n{res.stderr}")
        print(f"[OK] 'kubectl kustomize {env_dir}' ejecutado y validado exitosamente.")
    else:
        print("[INFO] 'kubectl' no encontrado en PATH. Omisión de renderizado kustomize local.")

    # 9. Gate de despliegue para QA y Producción:
    # Si el ambiente requiere proveedor persistente y no estamos en modo solo-render, detener antes de transferencia SCP.
    if cfg["requires_persistent_provider"] and not render_only:
        print(f"\n================================================================================")
        print(f"GATE DE DESPLIEGUE - BLOQUEO OBLIGATORIO DE SEGURIDAD PREVIO A {env.upper()}:")
        print(f"La solución tiene configurado '{signing_provider}' para {env}.")
        print(f"Conforme a la decisión normativa del 2026-10-22, la integración de un proveedor")
        print(f"persistente (AWS KMS, Kubernetes Secret o PFX) está pendiente como backlog obligatorio.")
        print(f"El despliegue a {env} se detiene exitosamente ANTES de la transferencia al servidor.")
        print(f"Consulte BACKLOG_SEGURIDAD_PRODUCTIVA.md para los criterios de salida a producción.")
        print(f"================================================================================\n")
        sys.exit(2)

    print(f"\nRenderizado y validación de manifiestos para '{env}' completado con éxito.")


def main():
    parser = argparse.ArgumentParser(description="Renderiza y valida manifiestos de Kubernetes para COBROUP.")
    parser.add_argument("--env", required=True, choices=["dev", "qa", "prod"], help="Ambiente objetivo.")
    parser.add_argument("--base-dir", default=".", help="Directorio raíz del repositorio de ambientes.")
    parser.add_argument(
        "--render-only",
        action="store_true",
        help="Solo renderiza y valida estructura/kustomize sin activar el gate de detención de transferencia.",
    )
    args = parser.parse_args()

    render_manifests(args.env, args.base_dir, render_only=args.render_only)


if __name__ == "__main__":
    main()
