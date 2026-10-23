#!/usr/bin/env python3
"""
verify_ssh_host.py - Autenticación y pinning estricto de host SSH (Regla B-23).

Verifica la huella SHA-256 de la clave pública ED25519 presentada por el servidor
contra la variable de entorno SSH_HOST_ED25519_FINGERPRINT antes de cualquier transmisión de datos.

Garantías:
1. Rechaza conexiones si la huella está ausente, malformada o no coincide.
2. Exige exactamente una clave ED25519 presentada por el servidor.
3. Genera un archivo known_hosts temporal confiable con permisos 0600.
4. Jamás usa ssh-keyscan como única fuente de confianza; la confianza proviene
   exclusivamente de la comparación estricta con SSH_HOST_ED25519_FINGERPRINT.
5. Nunca expone ni imprime secretos, claves privadas ni datos sensibles.
"""

import argparse
import base64
import hashlib
import hmac
import os
import re
import shutil
import subprocess
import sys

FINGERPRINT_PREFIX = "SHA256:"


def validate_fingerprint_format(fingerprint_str: str) -> str:
    """Valida que la huella esperada tenga formato SHA256:<base64-32-bytes>."""
    if not fingerprint_str or not fingerprint_str.strip():
        sys.exit("ERROR B-23: La huella esperada SSH_HOST_ED25519_FINGERPRINT es obligatoria y no puede estar vacía.")

    stripped = fingerprint_str.strip()
    if not stripped.startswith(FINGERPRINT_PREFIX):
        sys.exit(
            f"ERROR B-23: Formato inválido en SSH_HOST_ED25519_FINGERPRINT ('{stripped}'). "
            f"Debe comenzar con el prefijo '{FINGERPRINT_PREFIX}'."
        )

    b64_part = stripped[len(FINGERPRINT_PREFIX) :].strip()
    # Agregar padding si fue omitido por OpenSSH
    padded = b64_part + "=" * ((4 - len(b64_part) % 4) % 4)
    try:
        raw_hash = base64.b64decode(padded, validate=True)
    except Exception as e:
        sys.exit(f"ERROR B-23: La porción Base64 de SSH_HOST_ED25519_FINGERPRINT no es válida: {e}")

    if len(raw_hash) != 32:
        sys.exit(
            f"ERROR B-23: Longitud inválida del digest SHA-256 en SSH_HOST_ED25519_FINGERPRINT. "
            f"Se esperaban 32 bytes (256 bits), se obtuvieron {len(raw_hash)} bytes."
        )

    return stripped


def compute_ed25519_fingerprint(pubkey_b64: str) -> str:
    """
    Calcula la huella SHA-256 estándar de OpenSSH para una clave pública en Base64.
    Decodifica el blob de la clave pública y calcula SHA-256, codificando el resultado
    en Base64 sin el padding '=' final, tal como lo hace ssh-keygen.
    """
    try:
        raw_key = base64.b64decode(pubkey_b64.strip(), validate=True)
    except Exception as e:
        sys.exit(f"ERROR B-23: El blob de clave pública ED25519 presentado no es Base64 válido: {e}")

    digest = hashlib.sha256(raw_key).digest()
    b64_digest = base64.b64encode(digest).decode("utf-8").rstrip("=")
    return f"{FINGERPRINT_PREFIX}{b64_digest}"


def extract_ed25519_keys(keyscan_output: str) -> list[tuple[str, str, str]]:
    """
    Parsea la salida de ssh-keyscan o archivo known_hosts, filtrando únicamente
    las líneas de clave tipo ssh-ed25519.
    Retorna lista de tuplas (host_pattern, key_type, pubkey_b64).
    """
    ed25519_keys = []
    for line in keyscan_output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            host_pattern, key_type, pubkey_b64 = parts[0], parts[1], parts[2]
            if key_type == "ssh-ed25519":
                ed25519_keys.append((host_pattern, key_type, pubkey_b64))

    return ed25519_keys


def verify_ssh_host(
    host: str,
    port: int,
    expected_fingerprint: str,
    out_known_hosts: str,
    keyscan_output_file: str | None = None,
) -> None:
    # 1. Validar formato de la huella esperada antes de cualquier conexión
    validated_expected = validate_fingerprint_format(expected_fingerprint)
    expected_normalized = validated_expected.rstrip("=")

    # 2. Obtener clave pública presentada por el host
    if keyscan_output_file:
        if not os.path.isfile(keyscan_output_file):
            sys.exit(f"ERROR B-23: Archivo de claves scan no encontrado: {keyscan_output_file}")
        with open(keyscan_output_file, "r", encoding="utf-8") as f:
            keyscan_output = f.read()
    else:
        keyscan_bin = shutil.which("ssh-keyscan")
        if not keyscan_bin:
            sys.exit("ERROR: La utilidad 'ssh-keyscan' no se encuentra disponible en el sistema.")

        cmd = [keyscan_bin, "-p", str(port), "-t", "ed25519", host]
        res = subprocess.run(cmd, capture_output=True, text=True)
        if res.returncode != 0:
            sys.exit(f"ERROR B-23: 'ssh-keyscan' falló con código {res.returncode}. No se pudo escanear el host.")
        keyscan_output = res.stdout

    # 3. Filtrar y validar claves ED25519 obtenidas
    ed25519_keys = extract_ed25519_keys(keyscan_output)
    if len(ed25519_keys) == 0:
        sys.exit(
            f"ERROR B-23: El servidor '{host}:{port}' no presentó ninguna clave pública 'ssh-ed25519'. "
            "Se requiere obligatoriamente una clave de host ED25519 para autenticación estricta."
        )

    if len(ed25519_keys) > 1:
        sys.exit(
            f"ERROR B-23: El servidor '{host}:{port}' presentó múltiples ({len(ed25519_keys)}) claves ED25519. "
            "Se exige exactamente una única clave ED25519 para evitar ambigüedades criptográficas."
        )

    host_pattern, key_type, pubkey_b64 = ed25519_keys[0]

    # 4. Calcular huella SHA-256 localmente
    computed_fp = compute_ed25519_fingerprint(pubkey_b64)
    computed_normalized = computed_fp.rstrip("=")

    # 5. Comparar huella en tiempo constante
    if not hmac.compare_digest(computed_normalized, expected_normalized):
        sys.exit(
            f"ERROR CRITICO DE SEGURIDAD B-23: La huella SSH del servidor no coincide con la huella registrada.\n"
            f"Conexión inmediatamente abortada para proteger las credenciales contra ataques MITM.\n"
            f"Host escaneado: {host}:{port}"
        )

    # 6. Escribir archivo known_hosts verificado con permisos estrictos 0600
    os.makedirs(os.path.dirname(os.path.abspath(out_known_hosts)), exist_ok=True)
    known_hosts_line = f"{host_pattern} {key_type} {pubkey_b64}\n"
    with open(out_known_hosts, "w", encoding="utf-8") as f:
        f.write(known_hosts_line)

    try:
        os.chmod(out_known_hosts, 0o600)
        if os.name == "posix":
            mode = os.stat(out_known_hosts).st_mode & 0o777
            if mode != 0o600:
                sys.exit(
                    f"ERROR CRITICO B-23: Falló la protección de permisos de '{out_known_hosts}'. "
                    f"Se esperaba modo 0600, pero se obtuvo {oct(mode)}."
                )
    except Exception as exc:
        if os.name == "posix":
            sys.exit(f"ERROR CRITICO B-23: Falló al proteger known_hosts con permisos 0600: {exc}")

    print(f"[OK] Autenticidad de host SSH verificada exitosamente para {host}:{port} contra huella ED25519 fijada.")


def main():
    parser = argparse.ArgumentParser(description="Verificación estricta de autenticidad de host SSH (B-23).")
    parser.add_argument("--host", required=True, help="Host o dirección IP del servidor SSH.")
    parser.add_argument("--port", type=int, default=22, help="Puerto SSH del servidor (default: 22).")
    parser.add_argument(
        "--expected-fingerprint",
        required=True,
        help="Huella SHA-256 esperada de la clave pública ED25519 (formato: SHA256:<base64>).",
    )
    parser.add_argument(
        "--out-known-hosts",
        required=True,
        help="Ruta de destino donde se escribirá el archivo known_hosts temporal verificado.",
    )
    parser.add_argument(
        "--keyscan-output-file",
        default=None,
        help="Opcional: Archivo con la salida de ssh-keyscan para pruebas locales/mock sin red.",
    )
    args = parser.parse_args()

    verify_ssh_host(
        host=args.host,
        port=args.port,
        expected_fingerprint=args.expected_fingerprint,
        out_known_hosts=args.out_known_hosts,
        keyscan_output_file=args.keyscan_output_file,
    )


if __name__ == "__main__":
    main()
