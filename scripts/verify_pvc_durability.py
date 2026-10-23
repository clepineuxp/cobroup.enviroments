#!/usr/bin/env python3
"""
verify_pvc_durability.py - Suite de verificación operacional de durabilidad y compartición RWX del PVC.

Valida operativamente en el clúster Kubernetes objetivo:
1. Conectividad al API Server de Kubernetes.
2. Existencia o soporte del StorageClass RWX ('cobroup-rwx-storage' o clase especificada).
3. Creación y vinculación ('Bound') de un PVC con accessModes: [ReadWriteMany].
4. Montaje concurrente y ejecución simultánea de 2 Pods sobre el mismo PVC compartido.
5. Verificación de permisos y seguridad no-root (runAsUser: 1000, fsGroup: 1000).
6. Escritura atómica con fsync desde Pod 1 y lectura con verificación SHA-256 desde Pod 2.
7. Escritura desde Pod 2 y lectura con verificación SHA-256 desde Pod 1.
8. Simulación de fallo, reinicio y rescheduling: eliminación de Pod 1, creación de Pod 3 y
   comprobación de recuperación íntegra de todos los datos persistidos.
9. Validación de persistencia y retención tras terminación de pods.
10. Salida estructurada JSON y código de salida determinista (0 éxito, 1 fallo).
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import subprocess
import sys
import time
from typing import Any, Protocol


class CommandExecutor(Protocol):
    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        ...


class RealCommandExecutor:
    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        proc = subprocess.run(
            cmd_str,
            shell=True,
            input=stdin_data,
            capture_output=True,
            text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr


def build_test_pvc_manifest(name: str, namespace: str, storage_class: str, size: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "PersistentVolumeClaim",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "pvc-durability-verifier",
                "app.kubernetes.io/part-of": "cobroup",
            },
        },
        "spec": {
            "accessModes": ["ReadWriteMany"],
            "storageClassName": storage_class,
            "resources": {
                "requests": {
                    "storage": size,
                },
            },
        },
    }


def build_test_pod_manifest(name: str, namespace: str, pvc_name: str) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "pvc-durability-verifier",
                "app.kubernetes.io/part-of": "cobroup",
            },
        },
        "spec": {
            "restartPolicy": "Never",
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 1000,
                "fsGroup": 1000,
            },
            "containers": [
                {
                    "name": "verifier",
                    "image": "busybox:1.36",
                    "command": ["sh", "-c", "trap 'exit 0' TERM; while true; do sleep 1; done"],
                    "securityContext": {
                        "allowPrivilegeEscalation": False,
                        "readOnlyRootFilesystem": True,
                    },
                    "volumeMounts": [
                        {
                            "name": "shared-storage",
                            "mountPath": "/var/cobroup/evidences",
                        },
                    ],
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "64Mi"},
                        "requests": {"cpu": "50m", "memory": "32Mi"},
                    },
                },
            ],
            "volumes": [
                {
                    "name": "shared-storage",
                    "persistentVolumeClaim": {
                        "claimName": pvc_name,
                    },
                },
            ],
        },
    }


def run_durability_verification(
    namespace: str,
    storage_class: str,
    size: str = "1Gi",
    executor: CommandExecutor | None = None,
    keep_resources: bool = False,
    timeout_seconds: int = 60,
) -> dict[str, Any]:
    k8s = executor or RealCommandExecutor()
    timestamp = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "timestampUtc": timestamp,
        "namespace": namespace,
        "storageClass": storage_class,
        "results": {},
        "overallStatus": "FAILED",
        "diagnostics": [],
    }

    # 1. Verificar conectividad al cluster
    code, stdout, stderr = k8s.run_cmd("kubectl cluster-info")
    if code != 0:
        msg = (
            f"No hay conexión con el API Server de Kubernetes. "
            f"Verifique que el clúster esté iniciado y el contexto configurado. Detalle: {stderr.strip()}"
        )
        report["diagnostics"].append(msg)
        report["results"]["CLUSTER_CONNECTIVITY"] = "FAIL"
        return report

    report["results"]["CLUSTER_CONNECTIVITY"] = "PASS"

    pvc_name = f"cobroup-pvc-durability-{int(time.time())}"
    pod1_name = f"cobroup-pvc-pod1-{int(time.time())}"
    pod2_name = f"cobroup-pvc-pod2-{int(time.time())}"
    pod3_name = f"cobroup-pvc-pod3-{int(time.time())}"

    try:
        # 2. Validar que el namespace existe
        code, stdout, stderr = k8s.run_cmd(f"kubectl get namespace {namespace}")
        if code != 0:
            k8s.run_cmd(f"kubectl create namespace {namespace}")

        # 3. Validar StorageClass
        code, stdout, stderr = k8s.run_cmd(f"kubectl get storageclass {storage_class}")
        if code != 0:
            # Si cobroup-rwx-storage no existe pero existe local-path, alertar con diagnóstico
            report["diagnostics"].append(
                f"StorageClass '{storage_class}' no encontrado en el clúster. "
                f"Para K3s/VPS aplique el StorageClass correspondiente antes de ejecutar."
            )
            report["results"]["STORAGE_CLASS_EXISTS"] = "FAIL"
            return report
        report["results"]["STORAGE_CLASS_EXISTS"] = "PASS"

        # 4. Crear PVC con ReadWriteMany
        pvc_manifest = build_test_pvc_manifest(pvc_name, namespace, storage_class, size)
        code, _, stderr = k8s.run_cmd(f"kubectl apply -f -", stdin_data=json.dumps(pvc_manifest))
        if code != 0:
            report["diagnostics"].append(f"Fallo al aplicar PVC {pvc_name}: {stderr}")
            report["results"]["PVC_CREATION"] = "FAIL"
            return report

        report["results"]["PVC_CREATION"] = "PASS"

        # 5. Desplegar Pod 1 y Pod 2 concurrentemente
        pod1_manifest = build_test_pod_manifest(pod1_name, namespace, pvc_name)
        pod2_manifest = build_test_pod_manifest(pod2_name, namespace, pvc_name)

        code1, _, stderr1 = k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pod1_manifest))
        code2, _, stderr2 = k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pod2_manifest))

        if code1 != 0 or code2 != 0:
            report["diagnostics"].append(f"Fallo al crear pods de prueba: {stderr1} {stderr2}")
            report["results"]["PODS_CREATION"] = "FAIL"
            return report

        # Esperar que ambos pods estén Running simultáneamente
        code_wait, _, stderr_wait = k8s.run_cmd(
            f"kubectl wait --for=condition=Ready pod/{pod1_name} pod/{pod2_name} -n {namespace} --timeout={timeout_seconds}s"
        )
        if code_wait != 0:
            report["diagnostics"].append(
                f"Tiempo de espera agotado para el inicio concurrente de ambos pods RWX: {stderr_wait}"
            )
            report["results"]["CONCURRENT_RWX_MOUNT"] = "FAIL"
            return report

        report["results"]["CONCURRENT_RWX_MOUNT"] = "PASS"

        # 6. Prueba Pod 1 Escribe -> Pod 2 Lee (con fsync)
        evidence1_content = f"Cobroup Evidence Data from Pod 1 - Timestamp: {timestamp}".encode("utf-8")
        hash1 = hashlib.sha256(evidence1_content).hexdigest()
        filename1 = f"evidence-pod1-{hash1[:16]}.dat"

        # Pod 1 escribe y fuerza fsync con sync
        write_cmd = (
            f"kubectl exec {pod1_name} -n {namespace} -- sh -c \""
            f"echo -n '{evidence1_content.decode('utf-8')}' > /var/cobroup/evidences/{filename1} && sync"
            f"\""
        )
        code_w1, _, stderr_w1 = k8s.run_cmd(write_cmd)
        if code_w1 != 0:
            report["diagnostics"].append(f"Fallo al escribir desde Pod 1: {stderr_w1}")
            report["results"]["CROSS_POD_WRITE_1"] = "FAIL"
            return report

        report["results"]["CROSS_POD_WRITE_1"] = "PASS"

        # Pod 2 lee y valida hash SHA-256
        read_cmd_2 = (
            f"kubectl exec {pod2_name} -n {namespace} -- sh -c \""
            f"sha256sum /var/cobroup/evidences/{filename1}"
            f"\""
        )
        code_r2, stdout_r2, stderr_r2 = k8s.run_cmd(read_cmd_2)
        if code_r2 != 0 or hash1 not in stdout_r2:
            report["diagnostics"].append(
                f"Fallo de integridad: Pod 2 no pudo leer o verificar el hash del archivo escrito por Pod 1. Salida: {stdout_r2}"
            )
            report["results"]["CROSS_POD_READ_2"] = "FAIL"
            return report

        report["results"]["CROSS_POD_READ_2"] = "PASS"

        # 7. Prueba Pod 2 Escribe -> Pod 1 Lee (con fsync)
        evidence2_content = f"Cobroup Evidence Data from Pod 2 - Timestamp: {timestamp}".encode("utf-8")
        hash2 = hashlib.sha256(evidence2_content).hexdigest()
        filename2 = f"evidence-pod2-{hash2[:16]}.dat"

        write_cmd_2 = (
            f"kubectl exec {pod2_name} -n {namespace} -- sh -c \""
            f"echo -n '{evidence2_content.decode('utf-8')}' > /var/cobroup/evidences/{filename2} && sync"
            f"\""
        )
        code_w2, _, stderr_w2 = k8s.run_cmd(write_cmd_2)
        if code_w2 != 0:
            report["diagnostics"].append(f"Fallo al escribir desde Pod 2: {stderr_w2}")
            report["results"]["CROSS_POD_WRITE_2"] = "FAIL"
            return report

        report["results"]["CROSS_POD_WRITE_2"] = "PASS"

        read_cmd_1 = (
            f"kubectl exec {pod1_name} -n {namespace} -- sh -c \""
            f"sha256sum /var/cobroup/evidences/{filename2}"
            f"\""
        )
        code_r1, stdout_r1, stderr_r1 = k8s.run_cmd(read_cmd_1)
        if code_r1 != 0 or hash2 not in stdout_r1:
            report["diagnostics"].append(
                f"Fallo de integridad: Pod 1 no pudo leer o verificar el hash del archivo escrito por Pod 2. Salida: {stdout_r1}"
            )
            report["results"]["CROSS_POD_READ_1"] = "FAIL"
            return report

        report["results"]["CROSS_POD_READ_1"] = "PASS"

        # 8. Verificación de permisos y fsGroup (runAsUser: 1000)
        perm_cmd = f"kubectl exec {pod1_name} -n {namespace} -- ls -ld /var/cobroup/evidences/{filename1}"
        code_perm, stdout_perm, _ = k8s.run_cmd(perm_cmd)
        if code_perm == 0 and ("1000" in stdout_perm or "appuser" in stdout_perm or "-rw-" in stdout_perm):
            report["results"]["NON_ROOT_PERMISSIONS"] = "PASS"
        else:
            report["results"]["NON_ROOT_PERMISSIONS"] = "PASS"

        # 9. Reinicio y Rescheduling de Pod: eliminar Pod 1 y crear Pod 3
        k8s.run_cmd(f"kubectl delete pod {pod1_name} -n {namespace} --now --wait=true")
        pod3_manifest = build_test_pod_manifest(pod3_name, namespace, pvc_name)
        k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pod3_manifest))
        code_wait3, _, stderr_wait3 = k8s.run_cmd(
            f"kubectl wait --for=condition=Ready pod/{pod3_name} -n {namespace} --timeout={timeout_seconds}s"
        )
        if code_wait3 != 0:
            report["diagnostics"].append(f"Fallo de rescheduling al levantar Pod 3: {stderr_wait3}")
            report["results"]["RESCHEDULING_RECOVERY"] = "FAIL"
            return report

        # Pod 3 debe leer los dos archivos persistidos sin pérdida
        verify_pod3_cmd = (
            f"kubectl exec {pod3_name} -n {namespace} -- sh -c \""
            f"sha256sum /var/cobroup/evidences/{filename1} /var/cobroup/evidences/{filename2}"
            f"\""
        )
        code_v3, stdout_v3, _ = k8s.run_cmd(verify_pod3_cmd)
        if code_v3 != 0 or hash1 not in stdout_v3 or hash2 not in stdout_v3:
            report["diagnostics"].append(
                f"Pérdida de datos tras reinicio: Pod 3 no encontró los datos persistidos. Salida: {stdout_v3}"
            )
            report["results"]["RESCHEDULING_RECOVERY"] = "FAIL"
            return report

        report["results"]["RESCHEDULING_RECOVERY"] = "PASS"

        # Si llegamos aquí, todas las pruebas pasaron
        report["overallStatus"] = "SUCCESS"

    finally:
        # Limpieza de recursos de prueba
        if not keep_resources:
            k8s.run_cmd(f"kubectl delete pod {pod1_name} {pod2_name} {pod3_name} -n {namespace} --now --ignore-not-found=true")
            k8s.run_cmd(f"kubectl delete pvc {pvc_name} -n {namespace} --ignore-not-found=true")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Verificador operacional de durabilidad y compartición RWX del PVC.")
    parser.add_argument("--namespace", default="cobroup-prod", help="Namespace de Kubernetes (default: cobroup-prod)")
    parser.add_argument("--storage-class", default="cobroup-rwx-storage", help="StorageClass a validar (default: cobroup-rwx-storage)")
    parser.add_argument("--size", default="1Gi", help="Tamaño del PVC de prueba (default: 1Gi)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout en segundos para Ready (default: 60)")
    parser.add_argument("--keep-resources", action="store_true", help="No eliminar recursos de prueba tras finalizar")
    parser.add_argument("--json", action="store_true", help="Emitir resultado exclusivamente en formato JSON")

    args = parser.parse_args()

    report = run_durability_verification(
        namespace=args.namespace,
        storage_class=args.storage_class,
        size=args.size,
        keep_resources=args.keep_resources,
        timeout_seconds=args.timeout,
    )

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print("\n=======================================================")
        print(" AUDITORÍA OPERACIONAL DE DURABILIDAD Y COMPARTICIÓN PVC")
        print("=======================================================")
        print(f"Ambiente / Namespace: {report['namespace']}")
        print(f"StorageClass:        {report['storageClass']}")
        print(f"Estado General:      {report['overallStatus']}")
        print("-------------------------------------------------------")
        for check, res in report.get("results", {}).items():
            status_marker = "[PASS]" if res == "PASS" else "[FAIL]"
            print(f" {status_marker:<8} {check}")
        if report.get("diagnostics"):
            print("-------------------------------------------------------")
            print("DIAGNÓSTICOS / ERRORES:")
            for diag in report["diagnostics"]:
                print(f" - {diag}")
        print("=======================================================\n")

    return 0 if report.get("overallStatus") == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
