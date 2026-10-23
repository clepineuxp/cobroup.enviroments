#!/usr/bin/env python3
"""Verifica la durabilidad de un PVC RWO sobre un StorageClass de Kubernetes.

La prueba monta el PVC en un pod no-root, escribe evidencia, elimina el pod y
monta el mismo claim en un segundo pod. Los pods nunca usan el volumen de forma
concurrente, por lo que el flujo es compatible con ``ReadWriteOnce``.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import subprocess
import sys
import time
from typing import Any, Protocol


class CommandExecutor(Protocol):
    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        ...


class RealCommandExecutor:
    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        proc = subprocess.run(cmd_str, shell=True, input=stdin_data, capture_output=True, text=True)
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
            "accessModes": ["ReadWriteOnce"],
            "storageClassName": storage_class,
            "resources": {"requests": {"storage": size}},
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
            "securityContext": {"runAsNonRoot": True, "runAsUser": 1000, "fsGroup": 1000},
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
                        {"name": "storage", "mountPath": "/var/cobroup/evidences"},
                    ],
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "64Mi"},
                        "requests": {"cpu": "50m", "memory": "32Mi"},
                    },
                },
            ],
            "volumes": [
                {"name": "storage", "persistentVolumeClaim": {"claimName": pvc_name}},
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

    code, _, stderr = k8s.run_cmd("kubectl cluster-info")
    if code != 0:
        report["diagnostics"].append(
            "No hay conexión con el API Server de Kubernetes. Verifique que el "
            f"clúster esté iniciado y el contexto configurado. Detalle: {stderr.strip()}"
        )
        report["results"]["CLUSTER_CONNECTIVITY"] = "FAIL"
        return report
    report["results"]["CLUSTER_CONNECTIVITY"] = "PASS"

    suffix = int(time.time())
    pvc_name = f"cobroup-pvc-durability-{suffix}"
    pod1_name = f"cobroup-pvc-pod1-{suffix}"
    pod2_name = f"cobroup-pvc-pod2-{suffix}"

    try:
        code, _, _ = k8s.run_cmd(f"kubectl get namespace {namespace}")
        if code != 0:
            k8s.run_cmd(f"kubectl create namespace {namespace}")

        code, _, _ = k8s.run_cmd(f"kubectl get storageclass {storage_class}")
        if code != 0:
            report["diagnostics"].append(
                f"StorageClass '{storage_class}' no encontrado en el clúster. "
                "Verifique que el provisionador local-path esté instalado."
            )
            report["results"]["STORAGE_CLASS_EXISTS"] = "FAIL"
            return report
        report["results"]["STORAGE_CLASS_EXISTS"] = "PASS"

        pvc_manifest = build_test_pvc_manifest(pvc_name, namespace, storage_class, size)
        code, _, stderr = k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pvc_manifest))
        if code != 0:
            report["diagnostics"].append(f"Fallo al aplicar PVC {pvc_name}: {stderr}")
            report["results"]["PVC_CREATION"] = "FAIL"
            return report
        report["results"]["PVC_CREATION"] = "PASS"

        pod1_manifest = build_test_pod_manifest(pod1_name, namespace, pvc_name)
        code, _, stderr = k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pod1_manifest))
        if code != 0:
            report["diagnostics"].append(f"Fallo al crear el primer pod de prueba: {stderr}")
            report["results"]["INITIAL_RWO_MOUNT"] = "FAIL"
            return report

        code, _, stderr = k8s.run_cmd(
            f"kubectl wait --for=condition=Ready pod/{pod1_name} -n {namespace} --timeout={timeout_seconds}s"
        )
        if code != 0:
            report["diagnostics"].append(f"El primer pod no pudo montar el PVC RWO: {stderr}")
            report["results"]["INITIAL_RWO_MOUNT"] = "FAIL"
            return report
        report["results"]["INITIAL_RWO_MOUNT"] = "PASS"

        evidence1 = f"Cobroup PVC evidence before restart - Timestamp: {timestamp}".encode("utf-8")
        hash1 = hashlib.sha256(evidence1).hexdigest()
        filename1 = f"evidence-before-restart-{hash1[:16]}.dat"
        write1 = (
            f"kubectl exec {pod1_name} -n {namespace} -- sh -c \""
            f"echo -n '{evidence1.decode('utf-8')}' > /var/cobroup/evidences/{filename1} && sync\""
        )
        code, _, stderr = k8s.run_cmd(write1)
        if code != 0:
            report["diagnostics"].append(f"Fallo al escribir la evidencia inicial: {stderr}")
            report["results"]["INITIAL_WRITE"] = "FAIL"
            return report
        report["results"]["INITIAL_WRITE"] = "PASS"

        read1 = f"kubectl exec {pod1_name} -n {namespace} -- sha256sum /var/cobroup/evidences/{filename1}"
        code, stdout, _ = k8s.run_cmd(read1)
        if code != 0 or hash1 not in stdout:
            report["diagnostics"].append(
                f"La evidencia inicial no pasó la validación SHA-256. Salida: {stdout}"
            )
            report["results"]["INITIAL_READ_INTEGRITY"] = "FAIL"
            return report
        report["results"]["INITIAL_READ_INTEGRITY"] = "PASS"

        permission_cmd = f"kubectl exec {pod1_name} -n {namespace} -- ls -ln /var/cobroup/evidences/{filename1}"
        code, stdout, stderr = k8s.run_cmd(permission_cmd)
        if code != 0 or "1000" not in stdout:
            report["diagnostics"].append(
                f"No se pudieron confirmar permisos no-root sobre el archivo. Salida: {stdout or stderr}"
            )
            report["results"]["NON_ROOT_PERMISSIONS"] = "FAIL"
            return report
        report["results"]["NON_ROOT_PERMISSIONS"] = "PASS"

        code, _, stderr = k8s.run_cmd(f"kubectl delete pod {pod1_name} -n {namespace} --now --wait=true")
        if code != 0:
            report["diagnostics"].append(f"No se pudo eliminar el primer pod: {stderr}")
            report["results"]["POD_RECREATION"] = "FAIL"
            return report

        pod2_manifest = build_test_pod_manifest(pod2_name, namespace, pvc_name)
        code, _, stderr = k8s.run_cmd("kubectl apply -f -", stdin_data=json.dumps(pod2_manifest))
        if code != 0:
            report["diagnostics"].append(f"Fallo al recrear el pod con el mismo PVC: {stderr}")
            report["results"]["POD_RECREATION"] = "FAIL"
            return report

        code, _, stderr = k8s.run_cmd(
            f"kubectl wait --for=condition=Ready pod/{pod2_name} -n {namespace} --timeout={timeout_seconds}s"
        )
        if code != 0:
            report["diagnostics"].append(f"El pod recreado no pudo montar el PVC RWO: {stderr}")
            report["results"]["POD_RECREATION"] = "FAIL"
            return report
        report["results"]["POD_RECREATION"] = "PASS"

        read_after_restart = (
            f"kubectl exec {pod2_name} -n {namespace} -- "
            f"sha256sum /var/cobroup/evidences/{filename1}"
        )
        code, stdout, _ = k8s.run_cmd(read_after_restart)
        if code != 0 or hash1 not in stdout:
            report["diagnostics"].append(f"Pérdida de datos tras recrear el pod. Salida: {stdout}")
            report["results"]["RESTART_RECOVERY"] = "FAIL"
            return report
        report["results"]["RESTART_RECOVERY"] = "PASS"

        evidence2 = f"Cobroup PVC evidence after restart - Timestamp: {timestamp}".encode("utf-8")
        hash2 = hashlib.sha256(evidence2).hexdigest()
        filename2 = f"evidence-after-restart-{hash2[:16]}.dat"
        write2 = (
            f"kubectl exec {pod2_name} -n {namespace} -- sh -c \""
            f"echo -n '{evidence2.decode('utf-8')}' > /var/cobroup/evidences/{filename2} && sync\""
        )
        code, _, stderr = k8s.run_cmd(write2)
        if code != 0:
            report["diagnostics"].append(f"Fallo al escribir después de recrear el pod: {stderr}")
            report["results"]["POST_RESTART_WRITE"] = "FAIL"
            return report

        read2 = f"kubectl exec {pod2_name} -n {namespace} -- sha256sum /var/cobroup/evidences/{filename2}"
        code, stdout, _ = k8s.run_cmd(read2)
        if code != 0 or hash2 not in stdout:
            report["diagnostics"].append(
                f"La escritura posterior al reinicio no pasó la validación SHA-256. Salida: {stdout}"
            )
            report["results"]["POST_RESTART_WRITE"] = "FAIL"
            return report
        report["results"]["POST_RESTART_WRITE"] = "PASS"
        report["overallStatus"] = "SUCCESS"
    finally:
        if not keep_resources:
            k8s.run_cmd(
                f"kubectl delete pod {pod1_name} {pod2_name} -n {namespace} --now --ignore-not-found=true"
            )
            k8s.run_cmd(f"kubectl delete pvc {pvc_name} -n {namespace} --ignore-not-found=true")

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Verificador operacional de durabilidad de un PVC RWO.")
    parser.add_argument("--namespace", default="cobroup-prod", help="Namespace de Kubernetes")
    parser.add_argument("--storage-class", default="local-path", help="StorageClass (default: local-path)")
    parser.add_argument("--size", default="1Gi", help="Tamaño del PVC de prueba")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout en segundos para Ready")
    parser.add_argument("--keep-resources", action="store_true", help="No eliminar los recursos de prueba")
    parser.add_argument("--json", action="store_true", help="Emitir exclusivamente JSON")
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
        print("\n===============================================")
        print(" AUDITORÍA DE DURABILIDAD DEL PVC RWO")
        print("===============================================")
        print(f"Namespace:    {report['namespace']}")
        print(f"StorageClass: {report['storageClass']}")
        print(f"Estado:       {report['overallStatus']}")
        print("-----------------------------------------------")
        for check, result in report.get("results", {}).items():
            marker = "[PASS]" if result == "PASS" else "[FAIL]"
            print(f" {marker:<8} {check}")
        if report.get("diagnostics"):
            print("-----------------------------------------------")
            print("DIAGNÓSTICOS:")
            for diagnostic in report["diagnostics"]:
                print(f" - {diagnostic}")
        print("===============================================\n")

    return 0 if report.get("overallStatus") == "SUCCESS" else 1


if __name__ == "__main__":
    sys.exit(main())
