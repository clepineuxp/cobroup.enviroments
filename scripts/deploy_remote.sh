#!/usr/bin/env bash
# deploy_remote.sh - Orquestador unificado de despliegue remoto seguro (B-21 y B-23)
# Cumple estrictamente con:
# - Prohibición absoluta de deshabilitar la verificación de claves de host
# - Prohibición absoluta de descartar el archivo de hosts conocidos
# - Host pinning estricto contra SSH_HOST_ED25519_FINGERPRINT
# - Directo pipe de Secrets en memoria (0 YAML sensible persistido)
# - Rollout seguro y secuencial: Backend (180s) -> Admin-Backend (180s)

set -euo pipefail

# 1. Validación de variables obligatorias
if [ -z "${SSH_HOST:-}" ] || [ -z "${SSH_USER:-}" ] || [ -z "${SSH_KEY:-}" ] || [ -z "${SSH_HOST_ED25519_FINGERPRINT:-}" ]; then
  echo "ERROR B-23: Faltan variables SSH obligatorias (SSH_HOST, SSH_USER, SSH_KEY, SSH_HOST_ED25519_FINGERPRINT)." >&2
  exit 1
fi

ENV="${ENV:-}"
if [[ "$ENV" != "dev" && "$ENV" != "qa" && "$ENV" != "prod" ]]; then
  echo "ERROR: La variable ENV debe ser 'dev', 'qa' o 'prod'. Valor recibido: '$ENV'" >&2
  exit 1
fi

SSH_PORT="${SSH_PORT:-22}"
KUBERNETES_NAMESPACE="${KUBERNETES_NAMESPACE:-cobroup-$ENV}"

# 2. Creación de entorno temporal aislado (permisos 0700)
TMP_DIR=$(mktemp -d)
chmod 700 "$TMP_DIR"
DEPLOY_KEY="$TMP_DIR/deploy_key"
KNOWN_HOSTS="$TMP_DIR/known_hosts"

# Trap para garantizar destrucción del material confidencial en cualquier condición de salida
cleanup() {
  local exit_code=$?
  set +e
  rm -rf "$TMP_DIR"
  exit "$exit_code"
}
trap cleanup EXIT INT TERM

# Escribir clave privada temporalmente (permisos 0600) sin registrarla en logs
set +x
echo "$SSH_KEY" | tr -d '\r' > "$DEPLOY_KEY"
chmod 600 "$DEPLOY_KEY"

echo "==> [1/5] Verificando autenticidad del host SSH ($SSH_HOST:$SSH_PORT)..."
python scripts/verify_ssh_host.py \
  --host "$SSH_HOST" \
  --port "$SSH_PORT" \
  --expected-fingerprint "$SSH_HOST_ED25519_FINGERPRINT" \
  --out-known-hosts "$KNOWN_HOSTS"

SSH_COMMON_OPTS=(
  -p "$SSH_PORT"
  -i "$DEPLOY_KEY"
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$KNOWN_HOSTS"
  -o BatchMode=yes
)

SCP_COMMON_OPTS=(
  -P "$SSH_PORT"
  -i "$DEPLOY_KEY"
  -o StrictHostKeyChecking=yes
  -o UserKnownHostsFile="$KNOWN_HOSTS"
  -o BatchMode=yes
)

echo "==> [2/5] Aplicando Kubernetes Secrets en memoria vía pipe seguro (Zero Persistent YAML)..."
python scripts/render_manifests.py --env "$ENV" --emit-secrets-stream | \
  ssh -T "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$SSH_HOST" "kubectl apply -f -"

echo "==> [3/5] Preparando directorios en servidor remoto..."
ssh -T "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$SSH_HOST" "mkdir -p /opt/cobroup/deploys/$ENV /opt/cobroup/deploys/bootstrap"

echo "==> [4/5] Transfiriendo manifiestos no sensibles mediante SCP con host verificado..."
scp -r "${SCP_COMMON_OPTS[@]}" "$ENV"/* "$SSH_USER@$SSH_HOST:/opt/cobroup/deploys/$ENV/"
scp -r "${SCP_COMMON_OPTS[@]}" bootstrap/* "$SSH_USER@$SSH_HOST:/opt/cobroup/deploys/bootstrap/"

echo "==> [5/5] Aplicando manifiestos y ejecutando rollout secuencial seguro (Backend -> Admin-Backend)..."
ssh -T "${SSH_COMMON_OPTS[@]}" "$SSH_USER@$SSH_HOST" bash -s <<EOF
set -euo pipefail
kubectl apply -k /opt/cobroup/deploys/$ENV

echo "Reiniciando deployment/backend..."
kubectl rollout restart deployment/backend -n "$KUBERNETES_NAMESPACE"
kubectl rollout status deployment/backend -n "$KUBERNETES_NAMESPACE" --timeout=180s

echo "Reiniciando deployment/admin-backend..."
kubectl rollout restart deployment/admin-backend -n "$KUBERNETES_NAMESPACE"
kubectl rollout status deployment/admin-backend -n "$KUBERNETES_NAMESPACE" --timeout=180s

echo "Despliegue y rollouts completados exitosamente en namespace $KUBERNETES_NAMESPACE."
EOF

echo "==> Despliegue de $ENV completado con éxito."
