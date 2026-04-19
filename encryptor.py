"""
File Sensitivity Encryptor
==========================
Scans each file with scanner.py (Microsoft Presidio) to detect PII and
automatically selects the appropriate encryption method:

  Low    → AES-128-CBC  (symmetric encryption, 128-bit key)
  Medium → AES-192-CBC  (symmetric encryption, 192-bit key)
  High   → AES-256-GCM  (authenticated encryption, 256-bit key)

Usage:
    python encryptor.py file1.txt file2.txt
    python encryptor.py documents/
    python encryptor.py report.txt notes/ --keys-out my_keys.txt

Output files:
    <source_dir>/encrypted/<original>.<ext>

Key material (AES keys, IVs, nonces, tags) is appended to keys.txt
(or the file specified with --keys-out). Keep that file safe.
"""

import argparse
import os
import secrets
import sys
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Import scanner functions so classification drives encryption automatically
from scanner import scan_file, scan_directory, AnalyzerEngine


# ---------------------------------------------------------------------------
# AES-128 CBC  (low sensitivity)
# ---------------------------------------------------------------------------

def encrypt_aes128(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-128 in CBC mode.

    CBC (Cipher Block Chaining) XORs each plaintext block with the previous
    ciphertext block before encrypting, so identical plaintext blocks produce
    different ciphertext blocks.

    Returns:
        ciphertext  – encrypted bytes
        key         – 16-byte (128-bit) secret key  ← keep private
        iv          – 16-byte initialisation vector  (stored with ciphertext)
    """
    key = secrets.token_bytes(16)   # 128-bit key (cryptographically random)
    iv  = secrets.token_bytes(16)   # 128-bit IV  (random, not secret)

    # PKCS7 padding aligns plaintext to the 128-bit (16-byte) AES block boundary
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext, key, iv


# ---------------------------------------------------------------------------
# AES-192 CBC  (medium sensitivity)
# ---------------------------------------------------------------------------

def encrypt_aes192(plaintext: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-192 in CBC mode.

    AES-192 uses a 24-byte (192-bit) key, offering a stronger security margin
    than AES-128 while remaining fully reversible (unlike SHA-256).

    Returns:
        ciphertext  – encrypted bytes
        key         – 24-byte (192-bit) secret key  ← keep private
        iv          – 16-byte initialisation vector  (stored with ciphertext)
    """
    key = secrets.token_bytes(24)   # 192-bit key (cryptographically random)
    iv  = secrets.token_bytes(16)   # 128-bit IV  (random, not secret)

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext, key, iv


# ---------------------------------------------------------------------------
# AES-256 GCM  (high sensitivity)
# ---------------------------------------------------------------------------

def encrypt_aes256(plaintext: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt *plaintext* with AES-256 in GCM mode (authenticated encryption).

    GCM (Galois/Counter Mode) combines counter-mode encryption with a
    Galois-field MAC, producing an authentication tag that detects any
    tampering with the ciphertext.  No padding is needed in GCM.

    Returns:
        ciphertext  – encrypted bytes
        key         – 32-byte (256-bit) secret key  ← keep private
        nonce       – 12-byte nonce (stored with ciphertext, not secret)
        tag         – 16-byte authentication tag    (stored with ciphertext)
    """
    key   = secrets.token_bytes(32)  # 256-bit key
    nonce = secrets.token_bytes(12)  # 96-bit nonce (recommended size for GCM)

    cipher    = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag        = encryptor.tag  # 16-byte authentication tag

    return ciphertext, key, nonce, tag


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

def process_file(filepath: str, label: str, keys_file) -> dict:
    """
    Read *filepath*, apply the method for *label*, write the output file,
    and record key material in *keys_file*.

    File layout written to disk:
        AES-128-CBC  →  IV (16 B) + ciphertext
        AES-192-CBC  →  IV (16 B) + ciphertext
        AES-256-GCM  →  nonce (12 B) + tag (16 B) + ciphertext

    Embedding IV/nonce/tag in the output file is standard practice: they are
    not secret and must be available for decryption / verification.

    Returns a summary dict for reporting.
    Raises FileNotFoundError, ValueError, or OSError on failure.
    """
    path = Path(filepath)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {filepath}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {filepath}")

    plaintext = path.read_bytes()

    encrypted_dir = path.parent / "encrypted"
    encrypted_dir.mkdir(exist_ok=True)
    out_path = encrypted_dir / path.name

    if label == "low":
        # --- AES-128-CBC ---
        ciphertext, key, iv = encrypt_aes128(plaintext)

        # Prepend IV to ciphertext so the output file is self-contained
        out_path.write_bytes(iv + ciphertext)

        # Record secret key in the keys file (IV is stored in the output file)
        keys_file.write(f"[AES-128-CBC] {path.name}\n")
        keys_file.write(f"  Key : {key.hex()}\n")
        keys_file.write(f"  IV  : {iv.hex()}  (also prepended to output file)\n\n")

        method   = "AES-128-CBC"
        out_size = len(iv) + len(ciphertext)

    elif label == "medium":
        # --- AES-192-CBC ---
        ciphertext, key, iv = encrypt_aes192(plaintext)

        # Prepend IV to ciphertext so the output file is self-contained
        out_path.write_bytes(iv + ciphertext)

        keys_file.write(f"[AES-192-CBC] {path.name}\n")
        keys_file.write(f"  Key : {key.hex()}\n")
        keys_file.write(f"  IV  : {iv.hex()}  (also prepended to output file)\n\n")

        method   = "AES-192-CBC"
        out_size = len(iv) + len(ciphertext)

    else:  # high
        # --- AES-256-GCM ---
        ciphertext, key, nonce, tag = encrypt_aes256(plaintext)

        # Layout: nonce (12 B) | tag (16 B) | ciphertext
        out_path.write_bytes(nonce + tag + ciphertext)

        # Record secret key; nonce and tag are in the output file
        keys_file.write(f"[AES-256-GCM] {path.name}\n")
        keys_file.write(f"  Key   : {key.hex()}\n")
        keys_file.write(f"  Nonce : {nonce.hex()}  (also in output file bytes 0–11)\n")
        keys_file.write(f"  Tag   : {tag.hex()}   (also in output file bytes 12–27)\n\n")

        method   = "AES-256-GCM"
        out_size = len(nonce) + len(tag) + len(ciphertext)

    return {
        "input":     str(path),
        "output":    str(out_path),
        "method":    method,
        "label":     label.capitalize(),
        "in_bytes":  len(plaintext),
        "out_bytes": out_size,
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    """Print a formatted summary table of all processed files."""
    print(f"\n{'='*65}")
    print(f"  SCAN + ENCRYPTION SUMMARY  ({len(results)} file(s) processed)")
    print(f"{'='*65}\n")

    for r in results:
        entities = ", ".join(r.get("entities", [])) or "none"
        print(f"  File     : {r['input']}")
        print(f"  Detected : {entities}")
        print(f"  Label    : {r['label']}")
        print(f"  Method   : {r['method']}")
        print(f"  Output   : {r['output']}")
        print(f"  Size     : {r['in_bytes']} B  →  {r['out_bytes']} B")
        print()

    print(f"{'='*65}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Scan files with Presidio to detect PII, then encrypt each file "
            "automatically based on its sensitivity classification."
        )
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="One or more .txt files or directories to scan and encrypt",
    )
    parser.add_argument(
        "--keys-out", "-k",
        default="keys.txt",
        help="File to append key material to (default: keys.txt)",
    )
    args = parser.parse_args()

    # Initialize Presidio once — it loads an NLP model so this takes a moment
    print("Initializing Presidio Analyzer...")
    analyzer = AnalyzerEngine()

    # Collect scan results by scanning every target file/directory
    scan_results = []
    for target in args.targets:
        if os.path.isdir(target):
            # scan_directory recurses and returns one dict per .txt file found
            scan_results.extend(scan_directory(target, analyzer))
        elif os.path.isfile(target) and target.endswith(".txt"):
            scan_results.append(scan_file(target, analyzer))
        else:
            print(f"  [SKIP]  '{target}' is not a .txt file or directory", file=sys.stderr)

    if not scan_results:
        print("No .txt files found to process.")
        sys.exit(0)

    results = []
    errors  = []

    # Open keys file in append mode so repeated runs accumulate entries
    with open(args.keys_out, "a", encoding="utf-8") as keys_file:
        for scan in scan_results:
            filepath = scan["file"]
            # scanner.py returns "High" / "Medium" / "Low"; process_file expects lowercase
            label = scan["classification"].lower()
            print(f"  [SCAN]  {filepath}  →  {scan['classification']}"
                  f"  ({', '.join(scan['entities_found']) or 'no PII'})")
            try:
                result = process_file(filepath, label, keys_file)
                # Attach scanner findings to the result for the summary report
                result["entities"] = scan["entities_found"]
                results.append(result)
                print(f"  [OK]    {filepath}  →  {result['output']}")
            except (FileNotFoundError, ValueError, OSError) as exc:
                errors.append((filepath, str(exc)))
                print(f"  [ERROR] {filepath}: {exc}", file=sys.stderr)

    if results:
        print_summary(results)
        print(f"Key material written to: {args.keys_out}")

    if errors:
        print(f"\n{len(errors)} file(s) failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
