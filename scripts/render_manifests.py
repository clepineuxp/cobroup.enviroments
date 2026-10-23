#!/usr/bin/env python3
"""
render_manifests.py - Renderiza y valida de manera segura y reproducible
los manifiestos de Kubernetes de COBROUP para dev, qa y prod.

Decisión de Seguridad JWT (DECISION_AUTENTICACION_JWT.md & Remediación v9):
- Algoritmo exclusivo: HS256 con secreto simétrico independiente por ambiente.
- Secreto CSPRNG de mínimo 32 bytes (256 bits) transportado en Base64.
- Inyección en memoria/stdin vía pipe directo 'kubectl apply -f -'.
- NUNCA se escriben secretos en disco, YAML persistente, argumentos o logs (Regla B-22).
- Microservicios admin-backend y backend comparten Secret 'jwt-signing-secret'.
- Cadenas de conexión residen en 'admin-backend-secret' y 'backend-secret'.
- Frontends completamente aislados del secreto criptográfico.
- Contrato de rotación estricto serial:
    Jwt__ActiveKeyId
    Jwt__SigningKeyBase64
    Jwt__PreviousValidationKeys__0__KeyId
    Jwt__PreviousValidationKeys__0__SigningKeyBase64
- Verificación de separación entre ambientes mediante JWT_KEY_FINGERPRINTS_JSON.
"""

import argparse
import base64
import hashlib
import json
import os
import re
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
        "pvc_storage": "1Gi",
        "pvc_modes": ["ReadWriteOnce"],
        "required_mode": "ReadWriteOnce",
        "max_replicas_rwo": 1,
        "require_storage_class": False,
    },
    "qa": {
        "pvc_storage": "5Gi",
        "pvc_modes": ["ReadWriteOnce"],
        "required_mode": "ReadWriteOnce",
        "max_replicas_rwo": 1,
        "require_storage_class": True,
    },
    "prod": {
        "pvc_storage": "10Gi",
        "pvc_modes": ["ReadWriteMany"],
        "required_mode": "ReadWriteMany",
        "max_replicas_rwo": None,
        "require_storage_class": True,
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

KEY_ID_REGEX = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
HOSTNAME_REGEX = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$"
)

INGRESS_HOST_TOKENS = {
    "INGRESS_FRONTEND_HOST": "__INGRESS_FRONTEND_HOST__",
    "INGRESS_ADMIN_FRONTEND_HOST": "__INGRESS_ADMIN_FRONTEND_HOST__",
    "INGRESS_API_HOST": "__INGRESS_API_HOST__",
    "INGRESS_AUTH_HOST": "__INGRESS_AUTH_HOST__",
}
PROD_INGRESS_HOST_TOKENS = {
    "INGRESS_FRONTEND_ALIAS_HOST": "__INGRESS_FRONTEND_ALIAS_HOST__",
}


def validate_key_id(kid_name: str, kid_value: str) -> str:
    """Valida que el identificador de clave cumpla estrictamente con el formato requerido."""
    if not kid_value or not kid_value.strip():
        sys.exit(f"ERROR: El identificador '{kid_name}' es obligatorio y no puede estar vacío.")

    stripped = kid_value.strip()
    upper = stripped.upper()
    for marker in PLACEHOLDER_MARKERS:
        if marker in upper:
            sys.exit(f"ERROR: El identificador '{kid_name}' contiene un placeholder no permitido ('{marker}').")

    if not KEY_ID_REGEX.match(stripped):
        sys.exit(
            f"ERROR: El identificador '{kid_name}' ('{stripped}') no cumple con el formato requerido '^[A-Za-z0-9._-]{{1,64}}$'."
        )

    return stripped


def validate_hostname(variable_name: str, value: str) -> str:
    """Valida un hostname DNS público sin esquema, puerto, ruta ni comodines."""
    hostname = value.strip().lower()
    if not hostname:
        sys.exit(f"ERROR: La variable '{variable_name}' es obligatoria y no puede estar vacía.")
    if not HOSTNAME_REGEX.fullmatch(hostname):
        sys.exit(
            f"ERROR: La variable '{variable_name}' debe contener únicamente un hostname DNS válido "
            "(sin esquema, puerto, ruta ni wildcard)."
        )
    return hostname


def render_environment_hosts(env: str, env_dir: str) -> dict[str, str]:
    """Sustituye los hosts públicos en los YAML no sensibles usando variables del GitHub Environment."""
    host_tokens = dict(INGRESS_HOST_TOKENS)
    if env == "prod":
        host_tokens.update(PROD_INGRESS_HOST_TOKENS)

    hosts = {
        variable_name: validate_hostname(variable_name, os.environ.get(variable_name, ""))
        for variable_name in host_tokens
    }
    if len(set(hosts.values())) != len(hosts):
        sys.exit(f"ERROR: Los hosts públicos configurados para '{env}' deben ser distintos entre sí.")

    replacements = {
        token: hosts[variable_name]
        for variable_name, token in host_tokens.items()
    }
    replacement_counts = {token: 0 for token in replacements}

    for root, _, files in os.walk(env_dir):
        for filename in files:
            if not filename.endswith((".yaml", ".yml")):
                continue
            filepath = os.path.join(root, filename)
            with open(filepath, "r", encoding="utf-8") as manifest:
                content = manifest.read()

            rendered = content
            for token, hostname in replacements.items():
                count = rendered.count(token)
                replacement_counts[token] += count
                rendered = rendered.replace(token, hostname)

            if rendered != content:
                with open(filepath, "w", encoding="utf-8") as manifest:
                    manifest.write(rendered)

    missing_tokens = [token for token, count in replacement_counts.items() if count == 0]
    if missing_tokens:
        sys.exit(
            f"ERROR: Las plantillas de '{env}' no contienen los tokens de host esperados: "
            + ", ".join(missing_tokens)
        )

    return hosts


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


def validate_fingerprints_json(env: str, raw_active_bytes: bytes, fingerprints_json_str: str) -> None:
    """
    Verifica que la variable JWT_KEY_FINGERPRINTS_JSON contenga exactamente dev, qa, prod,
    que todos los fingerprints sean distintos y que el fingerprint de la clave activa coincida.
    NUNCA imprime el secreto, bytes ni fingerprints.
    """
    if not fingerprints_json_str or not fingerprints_json_str.strip():
        sys.exit("ERROR: La variable de repositorio 'JWT_KEY_FINGERPRINTS_JSON' es obligatoria.")

    try:
        data = json.loads(fingerprints_json_str.strip())
    except Exception:
        sys.exit("ERROR: 'JWT_KEY_FINGERPRINTS_JSON' no es un JSON válido.")

    if not isinstance(data, dict):
        sys.exit("ERROR: 'JWT_KEY_FINGERPRINTS_JSON' debe ser un objeto JSON con claves 'dev', 'qa', 'prod'.")

    required_envs = {"dev", "qa", "prod"}
    if set(data.keys()) != required_envs:
        sys.exit("ERROR: 'JWT_KEY_FINGERPRINTS_JSON' debe contener exactamente las claves 'dev', 'qa' y 'prod'.")

    # Validar formato hex SHA-256 de 64 caracteres
    sha256_regex = re.compile(r"^[0-9a-f]{64}$")
    fp_values = []
    for e_name, fp in data.items():
        if not isinstance(fp, str) or not sha256_regex.match(fp.lower()):
            sys.exit(f"ERROR: El fingerprint para el ambiente '{e_name}' en 'JWT_KEY_FINGERPRINTS_JSON' no es un SHA-256 válido.")
        fp_values.append(fp.lower())

    if len(set(fp_values)) != 3:
        sys.exit("ERROR CRITICO: Se detectaron fingerprints duplicados entre ambientes en 'JWT_KEY_FINGERPRINTS_JSON'. Cada ambiente debe tener una clave única.")

    # Calcular SHA-256 de los bytes decodificados de la clave activa en memoria
    computed_fp = hashlib.sha256(raw_active_bytes).hexdigest().lower()
    expected_fp = data[env].lower()

    if computed_fp != expected_fp:
        sys.exit(f"ERROR CRITICO: El fingerprint SHA-256 de la clave activa no coincide con el registrado para el ambiente '{env}'. Despliegue abortado.")


def emit_secrets_yaml(env: str, namespace: str) -> str:
    """
    Genera en memoria los manifiestos de Kubernetes Secrets codificados en base64
    para ser aplicados directamente por pipe a 'kubectl apply -f -'.
    NUNCA persiste estos datos en disco.
    """
    ops_db = os.environ.get("OPERATIONS_DATABASE_CONNECTIONSTRING", "").strip()
    ident_db = os.environ.get("IDENTITY_DATABASE_CONNECTIONSTRING", "").strip()
    jwt_active_b64 = os.environ.get("JWT_ACTIVE_SIGNING_KEY_BASE64", "").strip()
    jwt_prev_b64 = os.environ.get("JWT_PREVIOUS_SIGNING_KEY_BASE64", "").strip()
    jwt_prev_kid = os.environ.get("JWT_PREVIOUS_KEY_ID", "").strip()
    ghcr_user = os.environ.get("GHCR_USERNAME", "").strip()
    ghcr_token = os.environ.get("GHCR_TOKEN", "").strip()

    jwt_active_kid = os.environ.get("JWT_ACTIVE_KEY_ID", "").strip()
    jwt_active_kid = validate_key_id("JWT_ACTIVE_KEY_ID", jwt_active_kid)
    raw_active_bytes = validate_base64_secret(env, "JWT_ACTIVE_SIGNING_KEY_BASE64", jwt_active_b64)

    has_prev_b64 = bool(jwt_prev_b64)
    has_prev_kid = bool(jwt_prev_kid)
    if has_prev_b64 != has_prev_kid:
        sys.exit(
            "ERROR: Incoherencia en clave previa: 'JWT_PREVIOUS_KEY_ID' y 'JWT_PREVIOUS_SIGNING_KEY_BASE64' deben proporcionarse conjuntamente."
        )

    # 1. jwt-signing-secret (B-21: Identificadores y material criptográfico en un único Secret)
    jwt_data = {
        "Jwt__ActiveKeyId": base64.b64encode(jwt_active_kid.encode("utf-8")).decode("utf-8"),
        "Jwt__SigningKeyBase64": base64.b64encode(jwt_active_b64.encode("utf-8")).decode("utf-8"),
    }
    if has_prev_b64:
        valid_prev_kid = validate_key_id("JWT_PREVIOUS_KEY_ID", jwt_prev_kid)
        if valid_prev_kid == jwt_active_kid:
            sys.exit("ERROR: El 'JWT_PREVIOUS_KEY_ID' no puede ser idéntico al 'JWT_ACTIVE_KEY_ID'.")
        raw_prev_bytes = validate_base64_secret(env, "JWT_PREVIOUS_SIGNING_KEY_BASE64", jwt_prev_b64)
        if raw_prev_bytes == raw_active_bytes:
            sys.exit("ERROR: El material criptográfico de la clave anterior no puede ser idéntico al de la clave activa.")

        jwt_data["Jwt__PreviousValidationKeys__0__KeyId"] = base64.b64encode(
            valid_prev_kid.encode("utf-8")
        ).decode("utf-8")
        jwt_data["Jwt__PreviousValidationKeys__0__SigningKeyBase64"] = base64.b64encode(
            jwt_prev_b64.encode("utf-8")
        ).decode("utf-8")

    jwt_secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "jwt-signing-secret",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/part-of": "cobroup",
                "environment": env,
            },
        },
        "type": "Opaque",
        "data": jwt_data,
    }

    # 2. admin-backend-secret
    admin_secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "admin-backend-secret",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "admin-backend",
                "app.kubernetes.io/part-of": "cobroup",
                "environment": env,
            },
        },
        "type": "Opaque",
        "data": {
            "ConnectionStrings__IdentityDatabase": base64.b64encode(ident_db.encode("utf-8")).decode("utf-8")
        },
    }

    # 3. backend-secret
    backend_secret = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "backend-secret",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "backend",
                "app.kubernetes.io/part-of": "cobroup",
                "environment": env,
            },
        },
        "type": "Opaque",
        "data": {
            "ConnectionStrings__OperationsDatabase": base64.b64encode(ops_db.encode("utf-8")).decode("utf-8")
        },
    }

    docs = [jwt_secret, admin_secret, backend_secret]

    # 4. ghcr-secret (si se proporcionan credenciales)
    if ghcr_user and ghcr_token:
        auth_str = base64.b64encode(f"{ghcr_user}:{ghcr_token}".encode("utf-8")).decode("utf-8")
        docker_config = {
            "auths": {
                "ghcr.io": {
                    "username": ghcr_user,
                    "password": ghcr_token,
                    "auth": auth_str,
                }
            }
        }
        docker_json_bytes = json.dumps(docker_config).encode("utf-8")
        ghcr_secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {
                "name": "ghcr-secret",
                "namespace": namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "cobroup",
                    "environment": env,
                },
            },
            "type": "kubernetes.io/dockerconfigjson",
            "data": {
                ".dockerconfigjson": base64.b64encode(docker_json_bytes).decode("utf-8")
            },
        }
        docs.append(ghcr_secret)

    return "---\n" + "\n---\n".join(yaml.safe_dump(doc, sort_keys=False) for doc in docs)


def render_manifests(
    env: str,
    base_dir: str = ".",
    emit_secrets_only: bool = False,
    allow_rotation: bool = False,
) -> None:
    if env not in ENV_CONFIGS:
        sys.exit(f"ERROR: Ambiente desconocido '{env}'. Valores válidos: dev, qa, prod.")

    cfg = ENV_CONFIGS[env]
    env_dir = os.path.join(base_dir, env)
    namespace = os.environ.get("KUBERNETES_NAMESPACE", f"cobroup-{env}").strip()
    expected_namespace = f"cobroup-{env}"
    if namespace != expected_namespace:
        sys.exit(
            f"ERROR: KUBERNETES_NAMESPACE ('{namespace}') no coincide con el namespace requerido para '{env}' ('{expected_namespace}')."
        )

    # 1. Validar variables secretas requeridas
    ops_db = os.environ.get("OPERATIONS_DATABASE_CONNECTIONSTRING", "").strip()
    ident_db = os.environ.get("IDENTITY_DATABASE_CONNECTIONSTRING", "").strip()
    jwt_active_b64 = os.environ.get("JWT_ACTIVE_SIGNING_KEY_BASE64", "").strip()
    jwt_prev_b64 = os.environ.get("JWT_PREVIOUS_SIGNING_KEY_BASE64", "").strip()

    missing_secrets = []
    if not ops_db:
        missing_secrets.append("OPERATIONS_DATABASE_CONNECTIONSTRING")
    if not ident_db:
        missing_secrets.append("IDENTITY_DATABASE_CONNECTIONSTRING")
    if not jwt_active_b64:
        missing_secrets.append("JWT_ACTIVE_SIGNING_KEY_BASE64")

    if missing_secrets:
        sys.exit(f"ERROR: Faltan secretos requeridos para '{env}': {', '.join(missing_secrets)}")

    # 2. Validar variables no secretas
    jwt_active_kid = validate_key_id("JWT_ACTIVE_KEY_ID", os.environ.get("JWT_ACTIVE_KEY_ID", ""))
    jwt_prev_kid = os.environ.get("JWT_PREVIOUS_KEY_ID", "").strip()

    # 3. Validar claves criptográficas y reglas de rotación
    raw_active_bytes = validate_base64_secret(env, "JWT_ACTIVE_SIGNING_KEY_BASE64", jwt_active_b64)

    has_prev_key = bool(jwt_prev_b64)
    has_prev_kid = bool(jwt_prev_kid)
    if has_prev_key != has_prev_kid:
        sys.exit("ERROR: 'JWT_PREVIOUS_KEY_ID' y 'JWT_PREVIOUS_SIGNING_KEY_BASE64' deben estar ambos presentes o ambos ausentes.")

    raw_prev_bytes = None
    if has_prev_key:
        validated_prev_kid = validate_key_id("JWT_PREVIOUS_KEY_ID", jwt_prev_kid)
        if validated_prev_kid == jwt_active_kid:
            sys.exit("ERROR: El 'JWT_PREVIOUS_KEY_ID' no puede ser idéntico al 'JWT_ACTIVE_KEY_ID'.")

        raw_prev_bytes = validate_base64_secret(env, "JWT_PREVIOUS_SIGNING_KEY_BASE64", jwt_prev_b64)
        if raw_prev_bytes == raw_active_bytes:
            sys.exit("ERROR: El material criptográfico de la clave anterior no puede ser idéntico al de la clave activa.")

        # Regla A.3 / 20: Despliegues generales abortan si detectan una rotación no orquestada
        if not allow_rotation:
            sys.exit(
                "ERROR: Se detectó configuración de clave previa en despliegue general no orquestado. "
                "Las rotaciones JWT deben ejecutarse exclusivamente mediante el workflow 'rotate-jwt.yml'."
            )

    # 4. Validar separación entre ambientes con fingerprints JSON (Obligatorio - SYM-01 / I-31)
    fingerprints_json = os.environ.get("JWT_KEY_FINGERPRINTS_JSON", "").strip()
    if not fingerprints_json:
        sys.exit("ERROR: La variable de repositorio 'JWT_KEY_FINGERPRINTS_JSON' es obligatoria y debe configurarse.")
    validate_fingerprints_json(env, raw_active_bytes, fingerprints_json)

    # 5. Validar storage class para QA y Prod
    pvc_storage_class = os.environ.get("PVC_STORAGE_CLASS", "").strip()
    if cfg["require_storage_class"] and not pvc_storage_class:
        sys.exit(f"ERROR: 'PVC_STORAGE_CLASS' es obligatoria para el ambiente '{env}'.")

    # Si se solicitó emitir únicamente el stream de secretos para el pipe SSH
    if emit_secrets_only:
        sys.stdout.write(emit_secrets_yaml(env, namespace))
        return

    # 6. Renderizar hosts públicos y actualizar manifiestos no sensibles en disco
    if not os.path.isdir(env_dir):
        sys.exit(f"ERROR: No se encontró el directorio de manifiestos: {env_dir}")

    ingress_hosts = render_environment_hosts(env, env_dir)

    # Verificar kustomization.yaml: REGLA B-22 - NO debe contener secret.yaml ni ghcr-secret.yaml
    kustomization_path = os.path.join(env_dir, "kustomization.yaml")
    if os.path.isfile(kustomization_path):
        with open(kustomization_path, "r", encoding="utf-8") as f:
            kust_doc = yaml.safe_load(f) or {}
        resources = kust_doc.get("resources", [])
        for res_item in resources:
            if "secret.yaml" in res_item or "ghcr-secret.yaml" in res_item:
                sys.exit(f"ERROR B-22: 'kustomization.yaml' en '{env}' contiene recurso sensible '{res_item}'. Los secretos deben aplicarse exclusivamente en memoria.")

    # Actualizar ConfigMaps en admin-backend y backend: retirar cualquier identificador o dato JWT
    for svc_name in ["admin-backend", "backend"]:
        manifest_file = os.path.join(env_dir, svc_name, f"{svc_name}-manifest.yaml")
        if not os.path.isfile(manifest_file):
            sys.exit(f"ERROR: No se encontró el manifiesto de servicio: {manifest_file}")

        with open(manifest_file, "r", encoding="utf-8") as f:
            docs = list(yaml.safe_load_all(f))

        modified = False
        for doc in docs:
            if not doc:
                continue
            kind = doc.get("kind")
            meta = doc.get("metadata", {})
            name = meta.get("name")

            if kind == "ConfigMap" and name in ["admin-backend-config", "backend-config"]:
                data = doc.setdefault("data", {})
                # B-21: Los identificadores JWT residen exclusivamente en 'jwt-signing-secret'
                if "Jwt__ActiveKeyId" in data:
                    del data["Jwt__ActiveKeyId"]
                    modified = True
                if "Jwt__PreviousValidationKeys__0__KeyId" in data:
                    del data["Jwt__PreviousValidationKeys__0__KeyId"]
                    modified = True

            elif kind == "PersistentVolumeClaim" and name == "backend-evidence-pvc":
                spec = doc.setdefault("spec", {})
                if pvc_storage_class:
                    spec["storageClassName"] = pvc_storage_class
                modes = spec.get("accessModes", [])
                req_mode = cfg["required_mode"]
                if req_mode not in modes:
                    sys.exit(f"ERROR en {env}: PVC 'backend-evidence-pvc' debe incluir modo de acceso '{req_mode}'. Modos actuales: {modes}")
                modified = True

            elif kind == "Deployment" and name in ["admin-backend", "backend"]:
                spec = doc.get("spec", {})
                replicas = spec.get("replicas", 1)
                max_rwo = cfg["max_replicas_rwo"]
                if max_rwo is not None and replicas > max_rwo:
                    sys.exit(f"ERROR: Réplica múltiple ({replicas}) no permitida con almacenamiento ReadWriteOnce en '{env}'.")

                # Verificar que el Deployment monte jwt-signing-secret
                containers = spec.get("template", {}).get("spec", {}).get("containers", [])
                for container in containers:
                    env_from = container.get("envFrom", [])
                    secret_names = [e.get("secretRef", {}).get("name") for e in env_from if "secretRef" in e]
                    if "jwt-signing-secret" not in secret_names:
                        sys.exit(f"ERROR: Contenedor '{container.get('name')}' en {svc_name} debe incluir secretRef 'jwt-signing-secret'.")

        if modified:
            with open(manifest_file, "w", encoding="utf-8") as f:
                f.write("---\n" + "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in docs if d) + "\n")

    # 7. Escanear todo el directorio del ambiente para garantizar:
    #    a) Cero archivos secret.yaml
    #    b) Cero placeholders residuales
    #    c) Cero residuos PEM/RSA/JWKS
    #    d) Ninguna clave JWT expuesta en frontends
    #    e) Ningún identificador o secreto JWT en ConfigMaps ni manifiestos no sensibles (B-21)
    all_yaml_files = []
    for root, _, files in os.walk(env_dir):
        for file in files:
            if file == "secret.yaml" or file == "ghcr-secret.yaml":
                sys.exit(f"ERROR B-22: Archivo sensible persistido detectado en disco: {os.path.join(root, file)}")
            if file.endswith((".yaml", ".yml")):
                filepath = os.path.join(root, file)
                all_yaml_files.append(filepath)

                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()

                for marker in PLACEHOLDER_MARKERS:
                    if marker in content:
                        sys.exit(f"ERROR: Placeholder '{marker}' no resuelto en {os.path.relpath(filepath, base_dir)}")

                if "__INGRESS_" in content:
                    sys.exit(f"ERROR: Token de host no resuelto en {os.path.relpath(filepath, base_dir)}")

                for forbidden in FORBIDDEN_LEGACY_PATTERNS:
                    if forbidden in content:
                        sys.exit(f"ERROR: Residuo no permitido '{forbidden}' en {os.path.relpath(filepath, base_dir)}")

                rel_path = os.path.relpath(filepath, base_dir).replace("\\", "/")
                # Regla B-21: ConfigMaps y recursos no sensibles no deben contener estado JWT
                for forbidden_jwt in ["Jwt__ActiveKeyId", "Jwt__SigningKeyBase64", "Jwt__PreviousValidationKeys"]:
                    if forbidden_jwt in content:
                        sys.exit(
                            f"ERROR B-21: Se detectó configuración JWT ('{forbidden_jwt}') en manifiesto no sensible '{rel_path}'. "
                            f"Todo el estado criptográfico JWT debe residir exclusivamente en el Secret 'jwt-signing-secret'."
                        )

                if "frontend" in rel_path and not "admin-backend" in rel_path and not "backend" in rel_path:
                    if "jwt-signing-secret" in content or "SigningKeyBase64" in content or jwt_active_b64 in content:
                        sys.exit(f"ERROR CRITICO: Clave o Secret JWT expuesto a frontend en {rel_path}")

    # 8. Verificar que todos y únicamente los hosts configurados estén presentes en el Ingress.
    ingress_path = os.path.join(env_dir, "ingress.yaml")
    with open(ingress_path, "r", encoding="utf-8") as ingress_file:
        ingress_docs = [doc for doc in yaml.safe_load_all(ingress_file) if doc]

    configured_hosts = set(ingress_hosts.values())
    rendered_rule_hosts = {
        rule.get("host")
        for doc in ingress_docs
        for rule in doc.get("spec", {}).get("rules", [])
        if rule.get("host")
    }
    rendered_tls_hosts = {
        host
        for doc in ingress_docs
        for tls_entry in doc.get("spec", {}).get("tls", [])
        for host in tls_entry.get("hosts", [])
    }
    if rendered_rule_hosts != configured_hosts or rendered_tls_hosts != configured_hosts:
        sys.exit(
            f"ERROR: Los hosts renderizados en ingress.yaml para '{env}' no coinciden exactamente con las variables del GitHub Environment."
        )

    # 9. Validar con kubectl kustomize si la herramienta está disponible
    kubectl_bin = shutil.which("kubectl")
    if kubectl_bin:
        res = subprocess.run([kubectl_bin, "kustomize", env_dir], capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR: 'kubectl kustomize {env_dir}' falló:\n{res.stderr}")
        print(f"[OK] 'kubectl kustomize {env_dir}' ejecutado y validado exitosamente (0 secretos persistidos).")
    else:
        print("[INFO] 'kubectl' no encontrado en PATH. Omisión de renderizado kustomize local.")

    print(f"\n[OK] Manifiestos no sensibles para '{env}' validados y listos para SCP seguro.")


def main():
    parser = argparse.ArgumentParser(description="Renderiza y valida manifiestos de Kubernetes para COBROUP.")
    parser.add_argument("--env", required=True, choices=["dev", "qa", "prod"], help="Ambiente objetivo.")
    parser.add_argument("--base-dir", default=".", help="Directorio raíz del repositorio de ambientes.")
    parser.add_argument(
        "--emit-secrets-stream",
        action="store_true",
        help="Emite los Kubernetes Secrets dinámicamente en stdout para pipe seguro 'kubectl apply -f -' sobre SSH stdin.",
    )
    parser.add_argument(
        "--allow-rotation",
        action="store_true",
        help="Permite la inclusión de claves anteriores durante operaciones de rotación orquestadas.",
    )
    args = parser.parse_args()

    render_manifests(
        args.env,
        args.base_dir,
        emit_secrets_only=args.emit_secrets_stream,
        allow_rotation=args.allow_rotation,
    )


if __name__ == "__main__":
    main()
