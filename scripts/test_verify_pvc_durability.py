#!/usr/bin/env python3
"""Pruebas del verificador operacional de PVC RWO."""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(__file__))
from verify_pvc_durability import build_test_pvc_manifest, run_durability_verification


class MockCommandExecutor:
    def __init__(self):
        self.cluster_reachable = True
        self.storage_class_exists = True
        self.pods_ready = True
        self.restart_read_succeeds = True
        self.command_log = []
        self.stored_files = {}

    def run_cmd(self, cmd_str: str, stdin_data: str | None = None) -> tuple[int, str, str]:
        self.command_log.append({"cmd": cmd_str, "stdin": stdin_data})

        if "kubectl cluster-info" in cmd_str:
            if not self.cluster_reachable:
                return 1, "", "connection refused"
            return 0, "Kubernetes control plane is running", ""

        if "kubectl get namespace" in cmd_str:
            return 0, "cobroup-prod Active", ""

        if "kubectl get storageclass" in cmd_str:
            if not self.storage_class_exists:
                return 1, "", "storageclasses 'local-path' not found"
            return 0, "local-path rancher.io/local-path", ""

        if "kubectl apply -f -" in cmd_str:
            json.loads(stdin_data or "{}")
            return 0, "configured", ""

        if "kubectl wait --for=condition=Ready" in cmd_str:
            if not self.pods_ready:
                return 1, "", "timed out waiting for condition"
            return 0, "condition met", ""

        if "echo -n" in cmd_str and "/var/cobroup/evidences/" in cmd_str:
            parts = cmd_str.split("echo -n '")[1].split("' > /var/cobroup/evidences/")
            content = parts[0]
            filename = parts[1].split(" && sync")[0]
            self.stored_files[filename] = hashlib.sha256(content.encode("utf-8")).hexdigest()
            return 0, "", ""

        if "sha256sum /var/cobroup/evidences/" in cmd_str:
            filename = cmd_str.split("sha256sum /var/cobroup/evidences/")[1].split()[0].rstrip('"')
            if "pod2" in cmd_str and "before-restart" in filename and not self.restart_read_succeeds:
                return 1, "", "No such file or directory"
            file_hash = self.stored_files.get(filename)
            if file_hash is None:
                return 1, "", "No such file or directory"
            return 0, f"{file_hash}  /var/cobroup/evidences/{filename}", ""

        if "ls -ln" in cmd_str:
            return 0, "-rw-r--r-- 1 1000 1000 64 evidence.dat", ""

        if "kubectl delete" in cmd_str:
            return 0, "deleted", ""

        return 0, "", ""


class TestVerifyPvcDurability(unittest.TestCase):
    def test_manifest_uses_read_write_once(self):
        manifest = build_test_pvc_manifest("test", "cobroup-dev", "local-path", "1Gi")
        self.assertEqual(manifest["spec"]["accessModes"], ["ReadWriteOnce"])
        self.assertEqual(manifest["spec"]["storageClassName"], "local-path")

    def test_unreachable_cluster_fails_fast_with_diagnostic(self):
        mock = MockCommandExecutor()
        mock.cluster_reachable = False

        report = run_durability_verification("cobroup-prod", "local-path", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["CLUSTER_CONNECTIVITY"], "FAIL")
        self.assertTrue(any("No hay conexión" in item for item in report["diagnostics"]))

    def test_missing_storage_class_fails_with_diagnostic(self):
        mock = MockCommandExecutor()
        mock.storage_class_exists = False

        report = run_durability_verification("cobroup-prod", "local-path", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["STORAGE_CLASS_EXISTS"], "FAIL")
        self.assertTrue(any("StorageClass 'local-path'" in item for item in report["diagnostics"]))

    def test_full_rwo_restart_cycle_passes(self):
        report = run_durability_verification(
            "cobroup-prod", "local-path", executor=MockCommandExecutor()
        )

        self.assertEqual(report["overallStatus"], "SUCCESS")
        expected = {
            "CLUSTER_CONNECTIVITY",
            "STORAGE_CLASS_EXISTS",
            "PVC_CREATION",
            "INITIAL_RWO_MOUNT",
            "INITIAL_WRITE",
            "INITIAL_READ_INTEGRITY",
            "NON_ROOT_PERMISSIONS",
            "POD_RECREATION",
            "RESTART_RECOVERY",
            "POST_RESTART_WRITE",
        }
        self.assertEqual(set(report["results"]), expected)
        self.assertTrue(all(result == "PASS" for result in report["results"].values()))

    def test_restart_read_integrity_failure_aborts(self):
        mock = MockCommandExecutor()
        mock.restart_read_succeeds = False

        report = run_durability_verification("cobroup-prod", "local-path", executor=mock)
        self.assertEqual(report["overallStatus"], "FAILED")
        self.assertEqual(report["results"]["RESTART_RECOVERY"], "FAIL")


if __name__ == "__main__":
    unittest.main()
