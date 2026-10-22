# COBROUP - Entornos y Manifiestos de Kubernetes (GitOps)

> **Repositorio Oficial:** [https://github.com/clepineuxp/cobroup.enviroments.git](https://github.com/clepineuxp/cobroup.enviroments.git)  
> **Arquitectura:** GitOps declarativo con Kustomize, K3s, Ingress-NGINX y sustitución segura de secretos.

Este repositorio contiene las plantillas declarativas de Kubernetes (K3s), archivos Kustomize, Ingress y definiciones de secretos para los ambientes de **Desarrollo (dev)**, **Pruebas (qa)** y **Producción (prod)** de la plataforma **COBROUP**.

---

## 1. Versionado e Imágenes Docker (GHCR)

Las imágenes de contenedor se construyen y publican en **GitHub Container Registry (`ghcr.io`)** desde sus respectivos repositorios de código:

- `ghcr.io/clepineuxp/ms-cobroup-backend` (Operaciones, préstamos, clientes, pagos, agenda)
- `ghcr.io/clepineuxp/ms-cobroup-backendadmin` (Autoridad JWT, identidad multi-tenant y auditoría)
- `ghcr.io/clepineuxp/mf-cobroup-frontend` (PWA Recolector / Cobrador)
- `ghcr.io/clepineuxp/mf-cobroup-frontend-admin` (PWA Portal Administrativo)

### Estrategia de Tags por Ambiente

- **Dev**: tag `dev` o `dev-<commit-sha>`
- **QA**: tag `qa` o `qa-<commit-sha>`
- **Prod**: tag `latest` o semver `v1.x.x`

---

## 2. Mapeo de Dominios e Ingress

| Ambiente | Namespace | Componente | Dominio Ingress | Servicio Interno K3s |
|---|---|---|---|---|
| **Dev** | `cobroup-dev` | PWA Recolector | `dev.cobroup.com` | `frontend:8080` |
| **Dev** | `cobroup-dev` | Admin Portal | `dev-admin.cobroup.com` | `admin-frontend:8080` |
| **Dev** | `cobroup-dev` | Operations API | `dev-api.cobroup.com` | `backend:8080` |
| **Dev** | `cobroup-dev` | Identity / Auth | `dev-auth.cobroup.com` | `admin-backend:8080` |
|---|---|---|---|---|
| **QA** | `cobroup-qa` | PWA Recolector | `qa.cobroup.com` | `frontend:8080` |
| **QA** | `cobroup-qa` | Admin Portal | `qa-admin.cobroup.com` | `admin-frontend:8080` |
| **QA** | `cobroup-qa` | Operations API | `qa-api.cobroup.com` | `backend:8080` |
| **QA** | `cobroup-qa` | Identity / Auth | `qa-auth.cobroup.com` | `admin-backend:8080` |
|---|---|---|---|---|
| **Prod** | `cobroup-prod` | PWA Recolector | `cobroup.com` / `www.cobroup.com` | `frontend:8080` |
| **Prod** | `cobroup-prod` | Admin Portal | `admin.cobroup.com` | `admin-frontend:8080` |
| **Prod** | `cobroup-prod` | Operations API | `api.cobroup.com` | `backend:8080` |
| **Prod** | `cobroup-prod` | Identity / Auth | `auth.cobroup.com` | `admin-backend:8080` |

### Contrato de identidad vigente

COBROUP usa exclusivamente JWT firmados con `HS256` según `../cobroup.md/DECISION_AUTENTICACION_JWT.md`. Esta regla reemplaza definitivamente RSA, PEM/PFX, JWKS, proveedores efímeros/persistentes y banderas de acknowledge.
- Cada ambiente usa un secreto CSPRNG Base64 distinto, de 32 bytes o más: `DEV_JWT_SIGNING_KEY_BASE64`, `QA_JWT_SIGNING_KEY_BASE64` y `PROD_JWT_SIGNING_KEY_BASE64`.
- Dentro de un ambiente, el mismo valor se inyecta como `Jwt__SigningKeyBase64` exclusivamente en `admin-backend` (emite y valida) y `backend` (solo valida). Los frontends y otras cargas no reciben el Secret.
- Los valores reales viven en GitHub Environment Secrets/Kubernetes Secrets. Está prohibido escribirlos en Git, ConfigMap, imagen, logs, artefactos o archivos renderizados persistentes.
- El render y el arranque deben fallar ante secreto ausente, placeholder, Base64 inválido, menos de 32 bytes o configuración de algoritmo distinta de `HS256`. No existen valores predeterminados ni fallback.
- La rotación coordina clave activa y anteriores mediante `kid` en ambos backends y todas sus réplicas. Los controles productivos están en `../cobroup.md/BACKLOG_SEGURIDAD_FIRMA_SIMETRICA.md`.

### Contrato de almacenamiento de evidencias y archivos

Conforme a `../cobroup.md/DECISION_ALMACENAMIENTO_ARCHIVOS.md`:
- Todas las fotografías de evidencias y archivos binarios se almacenan en un `PersistentVolumeClaim` (PVC) de Kubernetes montado en `/var/cobroup/evidences`.
- En **Producción** con dos réplicas (`replicas: 2`), el PVC `backend-evidence-pvc` utiliza el modo de acceso compartido **`ReadWriteMany` (RWX)**.
- En **Dev** y **QA**, el PVC utiliza `ReadWriteOnce` (RWO) con capacidades de `1Gi` y `5Gi` respectivamente (`10Gi` en producción).
- La lógica de negocio y base de datos guardan exclusivamente claves relativas (`{tenantId}/{paymentId}/{hash}.{ext}`). El diseño desacoplado permite una sustitución futura por **AWS S3** (`Storage:Provider=S3`) mediante configuración e inyección de dependencias, sin reescribir Core, Domain ni contratos HTTP.


---

## 3. Estructura del Directorio

```text
cobroup.enviroments/
├── .github/
│   └── workflows/
│       ├── deploy-dev.yml              # Exporta manifiestos dev y bootstrap a /opt/cobroup/deploys/dev
│       ├── deploy-qa.yml               # Exporta manifiestos qa y bootstrap a /opt/cobroup/deploys/qa
│       └── deploy-prod.yml             # Exporta manifiestos prod y bootstrap a /opt/cobroup/deploys/prod
├── bootstrap/
│   └── cobroup-infra-bootstrap.yaml    # Namespaces cobroup-dev, cobroup-qa, cobroup-prod
├── dev/
│   ├── backend/                        # ConfigMap, Secret, Deployment, Service (Operaciones)
│   ├── admin-backend/                  # ConfigMap, Secret, Deployment, Service (Identidad)
│   ├── frontend/                       # ConfigMap, Secret, Deployment, Service (Recolector PWA)
│   ├── admin-frontend/                 # ConfigMap, Secret, Deployment, Service (Admin PWA)
│   ├── ingress.yaml                    # Reglas de enrutamiento TLS para dev.* (Ingress-NGINX)
│   ├── ghcr-secret.yaml                # Plantilla de autenticación GHCR
│   └── kustomization.yaml              # Manifiesto Kustomize para dev
├── qa/
│   ├── backend/, admin-backend/, ...   # Componentes configurados para QA
│   ├── ingress.yaml                    # Reglas de enrutamiento TLS para qa.*
│   └── kustomization.yaml
└── prod/
    ├── backend/, admin-backend/, ...   # Componentes para Producción (2 réplicas)
    ├── ingress.yaml                    # Reglas de enrutamiento TLS para producción
    └── kustomization.yaml
```

---

## 4. Configuración Requerida en GitHub

### Paso 1: Subir las Ramas Iniciales
```bash
git push -u origin main
git push -u origin dev
git push -u origin qa
```

### Paso 2: Crear el Entorno `cobroup`
En **Settings ➔ Environments ➔ New environment**: crear el entorno `cobroup`.

### Paso 3: Cargar Secretos (Secrets)
En **Settings ➔ Secrets and variables ➔ Actions**:
- `SSH_HOST`: IP pública de la VPS.
- `SSH_USER`: `deployer`.
- `SSH_KEY`: Clave privada SSH Ed25519.
- `SSH_PORT`: `22`.
- `GHCR_TOKEN`: PAT clásico de GitHub con scope `read:packages`.
- `DEV_OPERATIONSDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL operations en dev.
- `DEV_IDENTITYDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL identity en dev.
- `QA_OPERATIONSDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL operations en qa.
- `QA_IDENTITYDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL identity en qa.
- `PROD_OPERATIONSDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL operations en prod.
- `PROD_IDENTITYDATABASE_CONNECTIONSTRING`: Cadena PostgreSQL identity en prod.
- `DEV_JWT_SIGNING_KEY_BASE64`: secreto HS256 CSPRNG exclusivo de Dev, Base64 de 32 bytes o más.
- `QA_JWT_SIGNING_KEY_BASE64`: secreto HS256 CSPRNG exclusivo de QA, Base64 de 32 bytes o más.
- `PROD_JWT_SIGNING_KEY_BASE64`: secreto HS256 CSPRNG exclusivo de Prod, Base64 de 32 bytes o más.

*(Nota: los nombres RSA/PEM anteriores fueron retirados y no deben reintroducirse. Los secretos HS256 reales nunca se escriben en el repositorio.)*

### Paso 4: Cargar Variables
- `GHCR_USERNAME`: `clepineuxp`.

---

## 5. Guía de Despliegue en VPS

### Paso 1: Bootstrap de Infraestructura (Namespaces)

```bash
kubectl apply -f /opt/cobroup/deploys/bootstrap/cobroup-infra-bootstrap.yaml
```

### Paso 2: Autenticación con GitHub Container Registry (GHCR)

```bash
# Para DEV
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<GITHUB_USER> \
  --docker-password=<GITHUB_PAT_TOKEN> \
  --namespace=cobroup-dev

# Para QA
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<GITHUB_USER> \
  --docker-password=<GITHUB_PAT_TOKEN> \
  --namespace=cobroup-qa

# Para PROD
kubectl create secret docker-registry ghcr-secret \
  --docker-server=ghcr.io \
  --docker-username=<GITHUB_USER> \
  --docker-password=<GITHUB_PAT_TOKEN> \
  --namespace=cobroup-prod
```

### Paso 3: Despliegue Completo con Kustomize

```bash
# Desplegar ambiente DEV
kubectl apply -k /opt/cobroup/deploys/dev

# Desplegar ambiente QA
kubectl apply -k /opt/cobroup/deploys/qa

# Desplegar ambiente PROD
kubectl apply -k /opt/cobroup/deploys/prod
```

### Paso 4: Verificación del Estado

```bash
# Ver pods en dev
kubectl get pods -n cobroup-dev -o wide

# Ver servicios en dev
kubectl get svc -n cobroup-dev

# Ver ingress en dev
kubectl get ingress -n cobroup-dev
```

---

## 6. Flujo GitOps y Despliegue Continuo (CI/CD)

1. **Gestión de Manifiestos**:
   Al realizar push a las ramas `dev`, `qa` o `main`/`prod` de este repositorio `cobroup.enviroments`, el workflow de GitHub Actions:
   - Sustituye los placeholders de conexión (`${{Dev_OperationsDatabase__ConnectionString}}`, etc.) con los secrets de GitHub.
   - Copia mediante SCP los manifiestos renderizados al directorio `/opt/cobroup/deploys/<ambiente>` y el bootstrap a `/opt/cobroup/deploys/bootstrap` en la VPS.
2. **Despliegue de Código**:
   Al realizar push en los repositorios de microservicios (`MS.Cobroup.Backend`, `MS.Cobroup.BackendAdmin`, `MF.cobroup-frontend`, `MF.cobroup-frontend-admin`), su GitHub Action:
   - Ejecuta las pruebas automatizadas (gate de calidad).
   - Construye y publica la imagen en GHCR.
   - Se conecta por SSH a la VPS y ejecuta:
     ```bash
     kubectl apply -f /opt/cobroup/deploys/<env>/<component>/
     kubectl rollout restart deployment/<component> -n <namespace>
     kubectl rollout status deployment/<component> -n <namespace> --timeout=120s
     ```
