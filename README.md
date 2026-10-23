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
- Los GitHub Environments pueden usar el mismo valor para `JWT_ACTIVE_SIGNING_KEY_BASE64` cuando se requiere una clave compartida; debe ser CSPRNG en Base64 de 32 bytes o más.
- Dentro de un ambiente, el mismo valor se inyecta como `Jwt__SigningKeyBase64` exclusivamente en `admin-backend` (emite y valida) y `backend` (solo valida). Los frontends y otras cargas no reciben el Secret.
- Los valores reales viven en GitHub Environment Secrets/Kubernetes Secrets. Está prohibido escribirlos en Git, ConfigMap, imagen, logs, artefactos o archivos renderizados persistentes.
- El render y el arranque deben fallar ante secreto ausente, placeholder, Base64 inválido, menos de 32 bytes o configuración de algoritmo distinta de `HS256`. No existen valores predeterminados ni fallback.
- La rotación coordina clave activa y anteriores mediante `kid` en ambos backends y todas sus réplicas. Los controles productivos están en `../cobroup.md/BACKLOG_SEGURIDAD_FIRMA_SIMETRICA.md`.

### Contrato de almacenamiento de evidencias y archivos

Conforme a `../cobroup.md/DECISION_ALMACENAMIENTO_ARCHIVOS.md`:
- Todas las fotografías de evidencias y archivos binarios se almacenan en un `PersistentVolumeClaim` (PVC) de Kubernetes montado en `/var/cobroup/evidences`.
- En **Dev**, **QA** y **Prod**, `backend-evidence-pvc` sigue el patrón de almacenamiento local de K3s: `ReadWriteOnce` con `storageClassName: local-path` y capacidades de `1Gi`, `5Gi` y `10Gi` respectivamente.
- El PVC está separado del Deployment en `backend/backend-storage.yaml`, igual que el patrón de `media-storage.yaml` usado como referencia.
- El `backend` mantiene una sola réplica y estrategia `Recreate` en todos los ambientes para evitar montajes solapados del volumen local durante un rollout.
- `local-path` vincula los datos al nodo K3s donde se aprovisiona el volumen. La operación debe incluir copias de seguridad externas; este modelo no ofrece alta disponibilidad ni recuperación automática ante pérdida del nodo.
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
│   ├── backend/                        # PVC local-path, ConfigMap, Deployment y Service
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
    ├── backend/, admin-backend/, ...   # Componentes para Producción
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

### Paso 2: Crear los GitHub Environments

En **Settings ➔ Environments ➔ New environment** crear, con estos nombres exactos:

- `dev`
- `qa`
- `prod`

Los tres workflows de despliegue seleccionan explícitamente su Environment. Por ello se usan los mismos nombres de variables y secretos en los tres, pero cada Environment conserva sus propios valores.

### Paso 3: Crear los Environment Secrets

Crear estos secretos dentro de **cada** Environment (`dev`, `qa` y `prod`):

| Secret | Obligatorio | Contenido |
|---|---:|---|
| `OPERATIONS_DATABASE_CONNECTIONSTRING` | Sí | Cadena de conexión de Operations para ese ambiente. |
| `IDENTITY_DATABASE_CONNECTIONSTRING` | Sí | Cadena de conexión de Identity para ese ambiente. |
| `JWT_ACTIVE_SIGNING_KEY_BASE64` | Sí | Clave HS256 CSPRNG en Base64 válido de al menos 32 bytes. Puede repetirse en Dev, QA y Prod. |
| `JWT_PREVIOUS_SIGNING_KEY_BASE64` | Solo durante rotación | Clave anterior. Debe existir junto con `JWT_PREVIOUS_KEY_ID`; en estado estable debe estar ausente. |
| `SSH_KEY` | Sí | Clave privada SSH usada por el runner para desplegar. |
| `SSH_HOST` | Sí | IP o hostname del servidor SSH. |
| `SSH_USER` | Sí | Usuario remoto, por ejemplo `deployer`. |
| `SSH_PORT` | No | Puerto SSH. Si no existe, se usa `22`. |
| `GHCR_TOKEN` | Condicional | PAT con `read:packages` cuando `GITHUB_TOKEN` no pueda leer las imágenes privadas de los otros repositorios. |

`GITHUB_TOKEN` no se crea manualmente: GitHub Actions lo suministra automáticamente. Los nombres RSA/PEM anteriores fueron retirados y no deben reintroducirse.

### Paso 4: Crear las Environment Variables

Crear estas variables dentro de **cada** Environment:

| Variable | Obligatoria | Contenido |
|---|---:|---|
| `INGRESS_FRONTEND_HOST` | Sí | Host principal de la PWA, sin `https://`, puerto ni ruta. |
| `INGRESS_ADMIN_FRONTEND_HOST` | Sí | Host del portal administrativo. |
| `INGRESS_API_HOST` | Sí | Host público de Operations API. |
| `INGRESS_AUTH_HOST` | Sí | Host público de Identity/Auth. |
| `INGRESS_FRONTEND_ALIAS_HOST` | Solo `prod` | Alias público adicional del frontend (`www.cobroup.com`). No se crea en `dev` ni `qa`. |
| `JWT_ACTIVE_KEY_ID` | Sí | Identificador de la clave activa, por ejemplo `k1`. |
| `JWT_PREVIOUS_KEY_ID` | Solo durante rotación | Identificador anterior. Debe existir junto con `JWT_PREVIOUS_SIGNING_KEY_BASE64`; en estado estable debe estar ausente. |
| `JWT_KEY_FINGERPRINTS_JSON` | Sí | JSON con los SHA-256 de las claves activas: `{"dev":"<64 hex>","qa":"<64 hex>","prod":"<64 hex>"}`. Los tres valores pueden ser idénticos; cada despliegue valida que el suyo corresponda a `JWT_ACTIVE_SIGNING_KEY_BASE64`. |
| `SSH_HOST_ED25519_FINGERPRINT` | Sí | Huella fijada del host SSH en formato `SHA256:<base64>`. |
| `PVC_STORAGE_CLASS` | No | Permite sobrescribir la clase; por defecto todos los workflows usan la StorageClass incluida en K3s: `local-path`. |
| `KUBERNETES_NAMESPACE` | No | Si se crea, debe ser exactamente `cobroup-dev`, `cobroup-qa` o `cobroup-prod`. |
| `GHCR_USERNAME` | No | Usuario/organización de GHCR; si falta, se usa `github.actor`. |

Valores de host que deben configurarse actualmente:

| Environment | `INGRESS_FRONTEND_HOST` | `INGRESS_ADMIN_FRONTEND_HOST` | `INGRESS_API_HOST` | `INGRESS_AUTH_HOST` | `INGRESS_FRONTEND_ALIAS_HOST` |
|---|---|---|---|---|---|
| `dev` | `dev.cobroup.com` | `dev-admin.cobroup.com` | `dev-api.cobroup.com` | `dev-auth.cobroup.com` | No crear |
| `qa` | `qa.cobroup.com` | `qa-admin.cobroup.com` | `qa-api.cobroup.com` | `qa-auth.cobroup.com` | No crear |
| `prod` | `cobroup.com` | `admin.cobroup.com` | `api.cobroup.com` | `auth.cobroup.com` | `www.cobroup.com` |

El renderer valida que todos los hosts sean DNS válidos y distintos, sustituye los tokens de los manifiestos y comprueba que las reglas y certificados TLS del Ingress coincidan exactamente con las variables. `INGRESS_API_HOST` e `INGRESS_AUTH_HOST` también alimentan `API_URL`, `IDENTITY_URL` e `Identity__Issuer` para mantener consistencia entre el enrutamiento y las aplicaciones.

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
   - Obtiene secretos y variables del GitHub Environment correspondiente (`dev`, `qa` o `prod`).
   - Renderiza los hosts del Ingress y las URLs públicas de aplicación desde `INGRESS_FRONTEND_HOST`, `INGRESS_ADMIN_FRONTEND_HOST`, `INGRESS_API_HOST`, `INGRESS_AUTH_HOST` y, solo en Prod, `INGRESS_FRONTEND_ALIAS_HOST`.
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
