#!/usr/bin/env python3
"""
test_verify_pvc_durability.py - Pruebas unitarias para la suite de verificación operacional de PVC (B-09-OPS).
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from verify_pvc_durability import (
    run_durability_verification,
    build_test_pvc_manifest,
    build_test_pod_manifest,
)


class MockCommandExecutor:
    def __init__(self):
        self.cluster_reachable = True
        self.storage_class_exists = True
        self.pvc_bind_succeeds = True
        self.pods_ready_succeeds = True
        self.pod1_write_succeeds = True
        self.pod2_read_succeeds = True
        self.pod2_write_succeeds = True
        self.pod1_read_succeeds = True
        self.rescheduling_succeeds = True
        self.command_log = []
        self.stored_files = {}

    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        self.command_log.append({"cmd": cmd_str, "stdin": stdin_data})

        if "kubectl cluster-info" in cmd_str:
            if not self.cluster_reachable:
                return 1, "", "dial tcp 127.0.0.1:6443: connectex: No connection could be made because the target machine actively refused it."
            return 0, "Kubernetes control plane is running at https://127.0.0.1:6443", ""

        if "kubectl get namespace" in cmd_str:
            return 0, "NAME STATUS AGE\ncobroup-prod Active 10d", ""

        if "kubectl get storageclass" in cmd_str:
            if not self.storage_class_exists:
                return 1, "", "Error from server (NotFound): storageclasses 'cobroup-rwx-storage' not found"
            return 0, "NAME PROVISIONER RECLAIMPOLICY\ncobroup-rwx-storage rancher.io/local-path Retain", ""

        if "kubectl apply -f -" in cmd_str:
            return 0, "configured", ""

        if "kubectl wait --for=condition=Ready pod/" in cmd_str:
            if not self.pods_ready_succeeds:
                return 1, "", "timed out waiting for the condition on pods"
            return 0, "pod/pod1 condition met\npod/pod2 condition met", ""

        # Pod 1 Write
        if "echo -n" in cmd_str and "evidence-pod1" in cmd_str:
            if not self.pod1_write_succeeds:
                return 1, "", "write error: permission denied"
            # Extraer contenido y filename
            parts = cmd_str.split("echo -n '")[1].split("' > /var/cobroup/evidences/")
            content = parts[0]
            filename = parts[1].split(" && sync")[0]
            import hashlib
            self.stored_files[filename] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            return 0, "", ""

        # Pod 3 verification (multi-file)
        if "sha256sum" in cmd_str and "evidence-pod1" in cmd_str and "evidence-pod2" in cmd_str:
            if not self.rescheduling_succeeds:
                return 1, "", "data lost after reschedule"
            output_lines = [f"{h}  /var/cobroup/evidences/{f}" for f, h in self.stored_files.items()]
            return 0, "\n".join(output_lines), ""

        # Pod 2 Read
        if "sha256sum /var/cobroup/evidences/evidence-pod1" in cmd_str:
            if not self.pod2_read_succeeds:
                return 1, "", "No such file or directory"
            # Devolver el hash almacenado
            filename = [f for f in self.stored_files if "evidence-pod1" in f][0]
            h = self.stored_files[filename]
            return 0, f"{h}  /var/cobroup/evidences/{filename}", ""

        # Pod 2 Write
        if "echo -n" in cmd_str and "evidence-pod2" in cmd_str:
            if not self.pod2_write_succeeds:
                return 1, "", "write error"
            parts = cmd_str.split("echo -n '")[1].split("' > /var/cobroup/evidences/")
            content = parts[0]
            filename = parts[1].split(" && sync")[0]
            import hashlib
            self.stored_files[filename] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            return 0, "", ""

        # Pod 1 Read
        if "sha256sum /var/cobroup/evidences/evidence-pod2" in cmd_str:
            if not self.pod1_read_succeeds:
                return 1, "", "checksum failed"
            filename = [f for f in self.stored_files if "evidence-pod2" in f][0]
            h = self.stored_files[filename]
            return 0, f"{h}  /var/cobroup/evidences/{filename}", ""

        # Non-root permission check
        if "ls -ld" in cmd_str:
            return 0, "-rw-r--r-- 1 appuser 1000 64 Oct 23 18:00 /var/cobroup/evidences/file.dat", ""

        if "kubectl delete" in cmd_str:
            return 0, "deleted", ""

        return 0, "", ""


class TestVerifyPvcDurability(unittest.TestCase):
    def test_unreachable_cluster_fails_fast_with_diagnostic(self):
        mock = MockCommandExecutor()
        mock.cluster_reachable = False

        report = run_durability_verification("cobroup-prod", "cobroup-rwx-storage", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["CLUSTER_CONNECTIVITY"], "FAIL")
        self.assertTrue(any("No hay conexión con el API Server" in d for d in report["diagnostics"]))

    def test_missing_storage_class_fails_with_diagnostic(self):
        mock = MockCommandExecutor()
        mock.storage_class_exists = False

        report = run_durability_verification("cobroup-prod", "cobroup-rwx-storage", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["STORAGE_CLASS_EXISTS"], "FAIL")
        self.assertTrue(any("StorageClass 'cobroup-rwx-storage' no encontrado" in d for d in report["diagnostics"]))

    def test_full_durability_cycle_passes_all_checks(self):
        mock = MockCommandExecutor()

        report = run_durability_verification("cobroup-prod", "cobroup-rwx-storage", executor=mock)
        self.assertEqual(report["overallStatus"], "SUCCESS")
        self.assertEqual(report["results"]["CLUSTER_CONNECTIVITY"], "PASS")
        self.assertEqual(report["results"]["STORAGE_CLASS_EXISTS"], "PASS")
        self.assertEqual(report["results"]["PVC_CREATION"], "PASS")
        self.assertEqual(report["results"]["CONCURRENT_RWX_MOUNT"], "PASS")
        self.assertEqual(report["results"]["CROSS_POD_WRITE_1"], "PASS")
        self.assertEqual(report["results"]["CROSS_POD_READ_2"], "PASS")
        self.assertEqual(report["results"]["CROSS_POD_WRITE_2"], "PASS")
        self.assertEqual(report["results"]["CROSS_POD_READ_1"], "PASS")
        self.assertEqual(report["results"]["NON_ROOT_PERMISSIONS"], "PASS")
        self.assertEqual(report["results"]["RESCHEDULING_RECOVERY"], "PASS")

    def test_cross_pod_read_integrity_failure_aborts(self):
        mock = MockCommandExecutor()
        mock.pod2_read_succeeds = False

        report = run_durability_verification("cobroup-prod", "cobroup-rwx-storage", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["CROSS_POD_READ_2"], "FAIL")


if __name__ == "__main__":
    unittest.main()
