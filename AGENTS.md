# cobroup.environments — Registro Operativo de Agentes de IA

Este documento registra cronológicamente las intervenciones y decisiones realizadas por agentes en el repositorio `cobroup.environments`. Cada entrada es estrictamente append-only.

## Entradas cronológicas

### 2026-10-22 — Remediación Bloqueantes B-09 y B-13 (Auditoría v5): Almacenamiento PVC y Renderer Reproducible de Manifiestos

- **Solicitud**: Remediar los bloqueantes B-09 (almacenamiento durable en PVC) y B-13 (workflow de manifiestos con PyYAML faltante y script inline duplicado), documentados en la auditoría v5 (`cobroup.md/informe/auditoria-backend-csharp-2026-10-22-v5.html`).
- **Decisión de almacenamiento PVC→S3**:
  - Proveedor actual: PersistentVolumeClaim de Kubernetes montado en `/var/cobroup/evidences`. En producción (2 réplicas) requiere `ReadWriteMany` (10Gi).
  - Proveedor futuro previsto: AWS S3 por inyección de dependencias y configuración sin alterar los contratos HTTP ni la lógica de negocio.
- **Implementación técnica**:
  - **B-09 (Manifiestos Kubernetes)**:
    - `dev/backend/backend-manifest.yaml`: PVC `backend-evidences-pvc` (1Gi, `ReadWriteOnce`), volumen montado en `/var/cobroup/evidences`, variables `Storage__Provider: "FileSystem"` y `Storage__EvidencePath: "/var/cobroup/evidences"`, `securityContext` del contenedor con `fsGroup: 1000` y `runAsUser: 1000`.
    - `qa/backend/backend-manifest.yaml`: PVC `backend-evidences-pvc` (5Gi, `ReadWriteOnce`), volumen y variables homólogas.
    - `prod/backend/backend-manifest.yaml`: PVC `backend-evidences-pvc` (10Gi, `ReadWriteMany` para soporte de 2 réplicas concurrentes), volumen y variables homólogas.
    - Documentación en `README.md` con matriz de almacenamiento y requerimientos de StorageClass.
  - **B-13 (Pipeline CI/CD y Renderizado Reproducible)**:
    - `scripts/requirements.txt`: Declaración explícita de `PyYAML==6.0.2`.
    - `scripts/render_manifests.py`: Script modular y reutilizable para sustitución de variables y secretos PEM (formato multilínea o base64 en bloque literal YAML `|`), validación de variables requeridas, detección de placeholders no resueltos, validación sintáctica de todos los YAML con `yaml.safe_load_all`, validación estructural de Kubernetes (Deployment, PVC, Mount, Variables de Storage con exigencia de `ReadWriteMany` en producción) y validación post-render mediante `kubectl kustomize`. No imprime secretos en salida ni logs.
    - `.github/workflows/deploy-dev.yml`, `deploy-qa.yml`, `deploy-prod.yml`: Actualizados para instalar dependencias desde `scripts/requirements.txt` y ejecutar `python scripts/render_manifests.py --env <dev|qa|prod>` antes de cualquier transferencia remota por SCP/SSH.
    - `scripts/test_render_manifests.py`: Suite de 7 pruebas unitarias y de integración que validan el comportamiento con PEM multilínea, base64, fallos por variables vacías, YAML inválido, almacenamiento incorrecto y render completo con `kubectl kustomize`.
- **Archivos modificados/creados**:
  - Modificados: `dev/backend/backend-manifest.yaml`, `qa/backend/backend-manifest.yaml`, `prod/backend/backend-manifest.yaml`, `.github/workflows/deploy-dev.yml`, `.github/workflows/deploy-qa.yml`, `.github/workflows/deploy-prod.yml`, `README.md`.
  - Creados: `scripts/requirements.txt`, `scripts/render_manifests.py`, `scripts/test_render_manifests.py`, `AGENTS.md`.
- **Resultados de pruebas**:
  - 7/7 pruebas unitarias e integración en verde en `test_render_manifests.py`:
    - `test_missing_pyyaml_guidance_error`: Demuestra detección limpia si faltara la dependencia.
    - `test_valid_render_dev`: Renderiza dev completo y ejecuta `kubectl kustomize dev` exitosamente.
    - `test_valid_render_qa`: Renderiza qa completo y ejecuta `kubectl kustomize qa` exitosamente.
    - `test_valid_render_prod`: Renderiza prod completo, valida PVC `ReadWriteMany` y ejecuta `kubectl kustomize prod` exitosamente.
    - `test_render_fails_on_empty_secret`: Detiene el pipeline antes del despliegue si falta un secreto obligatorio.
    - `test_render_fails_on_malformed_yaml`: Detiene el pipeline ante YAML sintácticamente inválido.
    - `test_render_fails_when_prod_pvc_not_rwx`: Detiene el pipeline si el PVC de producción no especifica `ReadWriteMany`.
  - Validación post-render de `kubectl kustomize` ejecutada en dev, qa y prod con 0 errores.
- **Git**: Cambios preservados en working tree sobre rama `dev`; sin commit, push, merge, tag ni PR.

### 2026-10-22 — Decisión arquitectónica: Retiro de PEM del flujo activo, configuración de RSA efímero en Dev y Gate de despliegue en CI/CD

- **Rama de trabajo**: Creada y cambiada a `feature/diferir-pem-rsa-efimero` a partir de `dev` bajo autorización explícita del usuario.
- **Decisión obligatoria aplicada**:
  > COBROUP continuará usando JWT firmados. En la fase actual de desarrollo y validación no se configurará una clave privada externa en formato PEM. BackendAdmin utilizará un proveedor RSA efímero generado en memoria, habilitado de forma explícita y restringido a entornos no productivos. La clave y el `kid` cambian al reiniciar la instancia; en consecuencia, los JWT emitidos antes del reinicio pueden dejar de ser válidos. Este modo no se considera apto para producción, alta disponibilidad ni múltiples réplicas emisoras. La custodia de una clave persistente, su rotación, solapamiento de claves y recuperación operativa mediante Kubernetes Secret, PFX, PEM, AWS KMS u otro proveedor aprobado quedan registrados como backlog obligatorio previo a producción.
- **Modificaciones técnicas**:
  - **Secretos retirados**: `dev/admin-backend/secret.yaml`, `qa/admin-backend/secret.yaml` y `prod/admin-backend/secret.yaml` retiraron los placeholders `Jwt__KeyId` y `Jwt__PrivateKeyPem`, manteniendo únicamente `ConnectionStrings__IdentityDatabase`.
  - **ConfigMap Dev**: `dev/admin-backend/admin-backend-manifest.yaml` configurado con `Jwt__SigningProvider: "EphemeralRsa"` y `Jwt__AllowEphemeralSigning: "true"`.
  - **ConfigMap QA y Prod**: `qa/admin-backend/admin-backend-manifest.yaml` y `prod/admin-backend/admin-backend-manifest.yaml` configurados con `Jwt__SigningProvider: "PersistentRsa"`.
  - **Workflows GitHub Actions**: `.github/workflows/deploy-dev.yml`, `deploy-qa.yml` y `deploy-prod.yml` eliminaron las variables `*_JWT_KEY_ID` y `*_JWT_PRIVATE_KEY_PEM`.
  - **Renderer reproducible (`scripts/render_manifests.py`)**:
    - Eliminada la normalización y sustitución de claves PEM privadas.
    - Valida que `dev` use `EphemeralRsa` con `AllowEphemeralSigning=true`.
    - Bloquea explícitamente `EphemeralRsa` en QA y Prod.
    - Implementa gate de despliegue: detiene el pipeline con código de salida 2 antes de la transferencia SCP para QA y Prod mientras el proveedor persistente esté en backlog.
    - Agregado flag `--render-only` para validación local y pruebas.
    - Conserva validación integral de YAML, placeholders no resueltos, estructura PVC (`ReadWriteMany` en producción) y ejecución de `kubectl kustomize`.
- **Pruebas automatizadas**:
  - `scripts/test_render_manifests.py`: 9/9 pruebas en verde:
    1. `test_missing_pyyaml_guidance_error`: Detección clara de ausencia de PyYAML.
    2. `test_valid_render_dev`: Renderizado dev completo con `EphemeralRsa` y ejecución exitosa de `kubectl kustomize dev`.
    3. `test_qa_fails_with_ephemeral_rsa`: Rechazo estricto de proveedor efímero en QA.
    4. `test_qa_blocks_deployment_gate_for_backlog`: Gate detiene despliegue en QA con código 2 por backlog de proveedor persistente.
    5. `test_prod_blocks_deployment_gate_for_backlog`: Gate detiene despliegue en Prod con código 2 por backlog de proveedor persistente.
    6. `test_render_fails_on_empty_secret`: Detiene pipeline si falta `ConnectionStrings__IdentityDatabase`.
    7. `test_render_fails_on_malformed_yaml`: Detiene pipeline ante sintaxis YAML inválida.
    8. `test_render_fails_when_prod_pvc_not_rwx`: Detiene pipeline si el PVC de producción no es `ReadWriteMany`.
    9. `test_render_only_flag_renders_and_validates_qa_and_prod`: Validación estructural y `kubectl kustomize` de QA y Prod en modo `--render-only`.
  - Validación post-render de `kubectl kustomize`: Ejecutada en `dev`, `qa` y `prod` con 0 errores y sin referencias a claves PEM.
- **Git**: Cambios preservados en working tree sobre rama `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.

### 2026-10-22 — Remediación Hallazgo B-19: Mitigación de coexistencia de emisores efímeros mediante estrategia Recreate

- **Problema remediado (B-19)**:
  `dev/admin-backend/admin-backend-manifest.yaml` configuraba `replicas: 1` con `RollingUpdate` (`maxSurge: 1`, `maxUnavailable: 0`). Con claves RSA efímeras en memoria, cada instancia genera claves y `kid`s divergentes. Durante cada rollout coexistían temporalmente el pod anterior y el nuevo detrás del mismo Service `admin-backend`, provocando rechazos intermitentes de tokens.
- **Implementación técnica**:
  - `dev/admin-backend/admin-backend-manifest.yaml`: Modificada la estrategia de despliegue a `strategy: type: Recreate`. El pod anterior es terminado completamente antes de crear el nuevo, impidiendo cualquier solapamiento de emisores incompatibles.
  - `scripts/render_manifests.py`: Agregada validación estricta para `dev`: si `Jwt__SigningProvider == EphemeralRsa`, rechaza despliegues de `admin-backend` con `RollingUpdate` y `maxSurge > 0` o estrategias distintas a `Recreate`.
  - `README.md`: Documentada la justificación de `Recreate` y la aceptación formal de la breve indisponibilidad de segundos durante el reinicio para entornos de desarrollo.
- **Pruebas automatizadas**:
  - `scripts/test_render_manifests.py`: Agregada prueba negativa `test_dev_fails_when_rolling_update_overlaps_ephemeral_rsa` (10/10 pruebas en verde).
  - `kubectl kustomize dev`: Validado y confirmado `strategy: type: Recreate` con 0 errores.
- **Git**: Cambios preservados en working tree sobre rama `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.

### 2026-10-22 / 2026-10-23 — Migración integral a JWT simétrico HS256 por ambiente (GitOps)

- **Decisión aplicada**: `cobroup.md/DECISION_AUTENTICACION_JWT.md`, `MS.Cobroup.BackendAdmin/docs/decisions/0007-symmetric-hs256-per-environment.md` y `MS.Cobroup.Backend/docs/decisions/0005-symmetric-hs256-validation.md`.
- **Modificaciones técnicas**:
  - **Secretos Kubernetes actualizados**: `dev/admin-backend/secret.yaml`, `dev/backend/secret.yaml`, `qa/admin-backend/secret.yaml`, `qa/backend/secret.yaml`, `prod/admin-backend/secret.yaml` y `prod/backend/secret.yaml` ahora inyectan `Jwt__SigningKeyBase64` consumiendo `${{Dev_Jwt__SigningKeyBase64}}`, `${{Qa_Jwt__SigningKeyBase64}}` y `${{Prod_Jwt__SigningKeyBase64}}`.
  - **Aislamiento de Frontends**: Se verificó y garantizó que los frontends (`frontend`, `admin-frontend`) no reciben ni contienen material de secretos JWT.
  - **ConfigMaps actualizados**: Se eliminaron `Jwt__SigningProvider: "EphemeralRsa"`, `Jwt__SigningProvider: "PersistentRsa"`, `Jwt__AllowEphemeralSigning: "true"` e `Identity__JwksUri`. Se configuró `Jwt__ActiveKeyId: "k1"`.
  - **Estrategia de Despliegue**: Al ser el secreto simétrico idéntico entre réplicas mediante Kubernetes Secrets, se restauró `RollingUpdate` (`maxSurge: 1, maxUnavailable: 0`) eliminando la necesidad de `Recreate`.
  - **Workflows CI/CD**: Actualizados `deploy-dev.yml`, `deploy-qa.yml` y `deploy-prod.yml` para consumir los GitHub Secrets `DEV_JWT_SIGNING_KEY_BASE64`, `QA_JWT_SIGNING_KEY_BASE64` y `PROD_JWT_SIGNING_KEY_BASE64`.
  - **Renderer (`scripts/render_manifests.py`)**:
    - Validación criptográfica fail-fast: no vacío, sin placeholders, Base64 válido, >= 32 bytes (256 bits).
    - Detección de reutilización entre ambientes: falla críticamente si Dev, QA o Prod comparten el mismo valor de clave.
    - Rechazo estricto de residuos heredados: `PrivateKeyPem`, `PublicKeyPem`, `EphemeralRsa`, `PersistentRsa`, `JwksUri`, `JwksUrl`, `AllowEphemeralSigning`, `AcknowledgeNonProductionEphemeralRiskOutsideDevelopment`, `SigningProvider`.
    - Eliminado el gate de detención previa que bloqueaba despliegues por falta de proveedor persistente.
  - **Pruebas automatizadas (`scripts/test_render_manifests.py`)**: 16/16 pruebas en verde, cubriendo casos positivos y negativos (falta de clave, vacía, placeholder, base64 inválido, 31 bytes, 32 bytes, colisión entre ambientes, residuos legacy, aislamiento frontend y validación kustomize en dev, qa y prod).
- **Git**: Cambios preservados en working tree; sin commit, push, merge, tag ni PR.

### 2026-10-23 — Remediación obligatoria de hallazgos B-21 y B-23 (GitOps, Workflows y Orquestación)

- **Auditoría atendida**: `cobroup.md/informe/auditoria-backend-csharp-2026-10-23-v10.html` (Hallazgos B-21 y B-23).
- **Remediación B-21 (Rotación HS256 operacional, coordinada y recuperable)**:
  - **Secret criptográfico unificado**: `render_manifests.py` genera en memoria `jwt-signing-secret` conteniendo `Jwt__ActiveKeyId`, `Jwt__SigningKeyBase64`, y en pareja opcional `Jwt__PreviousValidationKeys__0__KeyId` y `Jwt__PreviousValidationKeys__0__SigningKeyBase64`.
  - **Limpieza de ConfigMaps**: Retirados `Jwt__ActiveKeyId` y cualquier referencia a JWT de `admin-backend-config` y `backend-config`. El script de render escanea los manifiestos en disco y falla si algún ConfigMap o archivo persistido contiene estado JWT.
  - **Detección de rotación no orquestada**: Despliegues generales (`deploy-dev.yml`, `deploy-qa.yml`, `deploy-prod.yml`) abortan inmediatamente si detectan un estado de clave anterior configurado sin pasar por el orquestador dedicado de rotación (`--allow-rotation`).
  - **Orquestador de rotación (`scripts/rotate_jwt.py`)**:
    - Lee `jwt-signing-secret` en memoria directamente de K8s.
    - Máquina de estados estricta: `prepublish` (activa k1, anterior k2), `activate` (activa k2, anterior k1, marca de tiempo `cobroup.com/activated-at`), `retire` (rechazo antes de 20 min / 1200s, Job K8s de revocación atómica para k1, aplica k2), `emergency` (escala `admin-backend` a 0, Job K8s de revocación total `--revoke-all`, aplica nueva clave, escala y reinicia en orden seguro).
    - Rollback en memoria: Si falla el rollout de `deployment/backend` (timeout 180s), revierte el Secret y NO reinicia `admin-backend`. Si falla `admin-backend` (timeout 180s), revierte el Secret y recupera ambos despliegues en orden seguro.
  - **Workflow dedicado `.github/workflows/rotate-jwt.yml`**:
    - Disparador manual `workflow_dispatch` con choices `environment` (`dev`, `qa`, `prod`) y `action` (`prepublish`, `activate`, `retire`, `emergency`).
    - Environment dinámico en job para vincular los Secrets de cada ambiente.
    - Concurrency group `jwt-rotation-${{ github.event.inputs.environment }}` para prevenir ejecuciones simultáneas.
- **Remediación B-23 (Autenticidad estricta SSH y pinning de host ED25519)**:
  - **Prohibición absoluta**: Eliminado de todos los workflows y scripts `StrictHostKeyChecking=no` y `UserKnownHostsFile=/dev/null`.
  - **Pinning de host ED25519 (`scripts/verify_ssh_host.py`)**:
    - Variable obligatoria por GitHub Environment: `SSH_HOST_ED25519_FINGERPRINT` (`SHA256:<digest-base64>`).
    - Obtiene clave pública ED25519 con `ssh-keyscan`, calcula SHA-256 localmente, valida en tiempo constante contra la variable preestablecida, y genera `known_hosts` temporal (modo 0600). Aborta antes de cualquier conexión remota si la huella no coincide, está ausente o malformada.
  - **Script unificado de despliegue remoto (`scripts/deploy_remote.sh`)**:
    - Directorio temporal `mktemp -d` (modo 0700) con `trap` para eliminación segura tanto en éxito como en fallo.
    - Verifica host antes de transmitir datos. Inyecta Secrets de K8s por pipe de stdin a `kubectl apply -f -` en memoria sin persistir YAMLs en disco.
    - Transferencia nativa por `scp` usando el `known_hosts` verificado y ejecución remota de rollout ordenado `deployment/backend` -> `deployment/admin-backend`.
  - **Workflows actualizados**: `deploy-dev.yml`, `deploy-qa.yml`, `deploy-prod.yml` migrados a pinning estricto con `verify_ssh_host.py` y `deploy_remote.sh`, retirando actions Appleboy.
- **Pruebas automatizadas**:
  - `scripts/test_render_manifests.py`: 16 pruebas.
  - `scripts/test_verify_ssh_host.py`: 9 pruebas (formato, match, mismatch, fallos previos a SSH).
  - `scripts/test_rotate_jwt.py`: 10 pruebas (máquina de estados, orden de rollout, rollback en memoria, tiempo mínimo de retiro, Job de revocación).
  - Total: 35/35 pruebas en verde en `cobroup.environments`.
- **Git**: Cambios preservados en working tree; sin commit, push, merge, tag ni PR.

### 2026-10-23 — Hosts de Ingress administrados por GitHub Environments

- **Solicitud**: Retirar los dominios públicos hardcodeados de los manifiestos y obtenerlos desde variables configuradas por ambiente en GitHub Actions, además de documentar el inventario completo de variables y secretos.
- **Implementación**:
  - Los workflows `deploy-dev.yml`, `deploy-qa.yml` y `deploy-prod.yml` exportan `INGRESS_FRONTEND_HOST`, `INGRESS_ADMIN_FRONTEND_HOST`, `INGRESS_API_HOST` e `INGRESS_AUTH_HOST` desde `vars`; Prod agrega `INGRESS_FRONTEND_ALIAS_HOST` para `www.cobroup.com`.
  - Los manifiestos de `dev`, `qa` y `prod` usan tokens no sensibles para todos los hosts del Ingress, `API_URL`, `IDENTITY_URL` e `Identity__Issuer`.
  - `scripts/render_manifests.py` exige y valida hostnames DNS, rechaza duplicados, sustituye los tokens y comprueba que los hosts de `rules` y `tls` coincidan exactamente con las variables del GitHub Environment.
  - `README.md` documenta los Environments `dev`, `qa` y `prod`, la matriz de hosts y el inventario completo de Environment Secrets y Environment Variables, incluyendo los campos opcionales y los usados exclusivamente durante rotación JWT.
- **Pruebas**:
  - `scripts/test_render_manifests.py`: 19/19 pruebas en verde, incluidas validación DNS, variable ausente, render de hosts y coherencia de URLs públicas.
  - Suite completa de `scripts`: 48/48 pruebas en verde.
  - `kubectl kustomize` validó satisfactoriamente `dev`, `qa` y `prod` después del render.
- **Git**: Cambios preservados en working tree sobre `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.

### 2026-10-23 — Provisionamiento dinámico NFS para StorageClass RWX

- **Solicitud**: Crear el despliegue necesario para disponer de una StorageClass capaz de aprovisionar el PVC de evidencias, especialmente el acceso `ReadWriteMany` requerido en Producción.
- **Decisión**: Reemplazar la falsa clase RWX basada en `rancher.io/local-path` por el provisionador oficial `nfs-subdir-external-provisioner`, que requiere un servidor NFS preexistente y accesible desde todos los nodos K3s.
- **Implementación**:
  - Nuevo `bootstrap/nfs-rwx-provisioner.yaml` con Namespace dedicado, ServiceAccount, RBAC mínimo, Deployment `v4.0.2` y StorageClass `cobroup-rwx-storage` con retención.
  - Nuevas variables obligatorias por GitHub Environment: `NFS_SERVER` y `NFS_PATH`; el renderer valida y sustituye ambos valores sin aceptar esquemas, puertos, rutas relativas o traversal.
  - Los workflows usan `cobroup-rwx-storage` como valor predeterminado de `PVC_STORAGE_CLASS`.
  - `deploy_remote.sh` aplica namespaces y almacenamiento antes de los Secrets/PVC, espera el rollout del provisionador y aborta con diagnóstico si detecta la antigua StorageClass cuyo `provisioner` inmutable es incompatible.
  - `README.md` documenta prerrequisitos NFS, variables, migración de la clase anterior y aplicación manual.
- **Pruebas**:
  - Agregada cobertura de validación y render NFS, estructura del Deployment y concordancia del nombre del provisionador con la StorageClass.
  - Suite completa: 49/49 pruebas en verde.
- **Git**: Cambios preservados en working tree sobre `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.

### 2026-10-23 — Ajuste definitivo del PVC al patrón local-path de Saviaup

- **Solicitud aclarada**: El PVC de COBROUP debe seguir el patrón de `saviaup.environments/dev/media/media-storage.yaml`: recurso independiente, `ReadWriteOnce` y `storageClassName: local-path`.
- **Decisión que reemplaza la propuesta NFS anterior**: Se elimina el provisionador NFS/RWX y sus variables porque no forman parte del patrón solicitado. K3s aprovisiona el volumen mediante su StorageClass `local-path`.
- **Implementación**:
  - Nuevos `dev/backend/backend-storage.yaml`, `qa/backend/backend-storage.yaml` y `prod/backend/backend-storage.yaml`, incluidos desde cada `kustomization.yaml`.
  - Los tres PVC usan `ReadWriteOnce`; las capacidades permanecen en `1Gi`, `5Gi` y `10Gi` para Dev, QA y Prod.
  - El backend usa una réplica y estrategia `Recreate` en todos los ambientes para evitar montajes solapados durante los rollouts.
  - `PVC_STORAGE_CLASS` pasa a ser opcional y su valor predeterminado es `local-path`; se retiraron `NFS_SERVER`, `NFS_PATH` y el bootstrap NFS.
  - El renderer valida el manifiesto separado, el modo RWO, la capacidad, la estrategia del Deployment y la inclusión del PVC en Kustomize.
  - El verificador operacional ahora prueba durabilidad RWO de forma secuencial: escritura, eliminación del primer pod, montaje del mismo PVC en otro pod y validación SHA-256 de los datos recuperados.
- **Consideración operativa**: `local-path` conserva los datos en el nodo que aloja el volumen; este diseño requiere respaldo externo y no ofrece alta disponibilidad ante pérdida del nodo.
- **Git**: Cambios preservados en working tree sobre `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.

### 2026-10-23 — Fingerprint JWT compartido entre GitHub Environments

- **Solicitud**: Permitir que `JWT_KEY_FINGERPRINTS_JSON` declare el mismo SHA-256 para `dev`, `qa` y `prod` cuando los tres ambientes usan la misma clave HS256 activa.
- **Implementación**:
  - `scripts/render_manifests.py` conserva la validación estricta del objeto JSON, las claves exactas `dev`, `qa` y `prod`, el formato SHA-256 hexadecimal y la correspondencia del valor del ambiente actual con `JWT_ACTIVE_SIGNING_KEY_BASE64`.
  - Se retiró únicamente la prohibición de fingerprints duplicados entre ambientes.
  - `README.md` documenta que tanto la clave activa como el fingerprint pueden compartirse entre los tres GitHub Environments.
  - La cobertura automatizada verifica explícitamente el mismo fingerprint para Dev, QA y Prod.
- **Almacenamiento**: Se confirma que `NFS_SERVER` y `NFS_PATH` no son requeridos ni están referenciados; el PVC utiliza `local-path`.
- **Git**: Cambios preservados en working tree sobre `feature/diferir-pem-rsa-efimero`; sin commit, push, merge, tag ni PR.
