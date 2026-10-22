# COBROUP - Entornos y Manifiestos de Kubernetes (GitOps)

Este repositorio contiene las plantillas declarativas de Kubernetes (K3s), archivos Kustomize, Ingress y definiciones de secretos para los ambientes de **Desarrollo (dev)**, **Pruebas (qa)** y **Producción (prod)** de la plataforma **COBROUP**.

---

## 1. Versionado e Imágenes Docker (GHCR)

Las imágenes de contenedor se construyen y publican en **GitHub Container Registry (`ghcr.io`)** desde sus respectivos repositorios de código:

- `ghcr.io/clepineuxp/ms-cobroup-backend` (Operaciones, préstamos, clientes, pagos, agenda)
- `ghcr.io/clepineuxp/ms-cobroup-backendadmin` (Identidad OpenIddict, multi-tenant, auditoría)
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

---

## 3. Estructura del Directorio

```text
cobroup.environments/
├── .github/
│   └── workflows/
│       ├── deploy-dev.yml              # Exporta manifiestos dev renderizados a /opt/cobroup/deploys/dev
│       ├── deploy-qa.yml               # Exporta manifiestos qa renderizados a /opt/cobroup/deploys/qa
│       └── deploy-prod.yml             # Exporta manifiestos prod renderizados a /opt/cobroup/deploys/prod
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

## 4. Guía de Despliegue en VPS

### Paso 1: Bootstrap de Infraestructura (Namespaces)

```bash
kubectl apply -f bootstrap/cobroup-infra-bootstrap.yaml
```

### Paso 2: Autenticación con GitHub Container Registry (GHCR)

En cada namespace (`cobroup-dev`, `cobroup-qa`, `cobroup-prod`), crear el secreto Docker para descargar imágenes privadas:

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

> **Nota**: El token personal (PAT) de GitHub requiere el scope `read:packages`.

### Paso 3: Despliegue Completo con Kustomize

Para desplegar un ambiente de forma atómica y completa en K3s:

```bash
# Desplegar ambiente DEV
kubectl apply -k ./dev

# Desplegar ambiente QA
kubectl apply -k ./qa

# Desplegar ambiente PROD
kubectl apply -k ./prod
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

## 5. Flujo GitOps y Despliegue Continuo (CI/CD)

1. **Gestión de Manifiestos**:
   Al realizar push a las ramas `dev`, `qa` o `main`/`prod` de este repositorio `cobroup.environments`, el workflow de GitHub Actions:
   - Sustituye los placeholders de conexión (`${{Dev_OperationsDatabase__ConnectionString}}`, etc.) con los secrets de GitHub.
   - Copia mediante SCP los manifiestos renderizados al directorio `/opt/cobroup/deploys/<ambiente>` en la VPS.
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
