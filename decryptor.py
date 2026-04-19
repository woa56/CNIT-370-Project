"""
File Sensitivity Decryptor
==========================
Reverses encryption produced by encryptor.py by reading key material from
keys.txt and applying the correct decryption method based on the keys file entry.

Usage:
    python decryptor.py encrypted/
    python decryptor.py encrypted/report.txt
    python decryptor.py encrypted/ --keys-in my_keys.txt

Output:
    encrypted/<file>  →  decrypted/<file>  (original filename, restored content)
"""

import argparse
import hashlib
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------------------------------------------------------------------
# keys.txt parser
# ---------------------------------------------------------------------------

def parse_keys_file(keys_path: str) -> dict:
    """
    Parse keys.txt and return a dict keyed by original filename.

    Each value is a dict with 'method' and the relevant key material:
        AES-128/192-CBC  →  {'method': 'AES-128-CBC', 'key': bytes, 'iv': bytes}
        AES-256-GCM      →  {'method': 'AES-256-GCM', 'key': bytes, 'nonce': bytes, 'tag': bytes}
        SHA-256          →  {'method': 'SHA-256', 'digest': str}

    If a filename appears multiple times (multiple runs), the LAST entry wins
    because encryptor.py generates a new key on every run.
    """
    keys: dict = {}
    path = Path(keys_path)

    if not path.exists():
        raise FileNotFoundError(f"Keys file not found: {keys_path}")

    text = path.read_text(encoding="utf-8")
    blocks = [b.strip() for b in text.split("\n\n") if b.strip()]

    for block in blocks:
        lines = block.splitlines()
        if not lines:
            continue

        header = lines[0].strip()

        # --- AES-128-CBC or AES-192-CBC ---
        if header.startswith("[AES-128-CBC]") or header.startswith("[AES-192-CBC]"):
            method = "AES-128-CBC" if header.startswith("[AES-128-CBC]") else "AES-192-CBC"
            filename = header.split("]", 1)[1].strip()
            entry = {"method": method}
            for line in lines[1:]:
                if line.strip().startswith("Key"):
                    entry["key"] = bytes.fromhex(line.split(":", 1)[1].strip().split()[0])
                elif line.strip().startswith("IV"):
                    entry["iv"] = bytes.fromhex(line.split(":", 1)[1].strip().split()[0])
            keys[filename] = entry

        # --- AES-256-GCM ---
        elif header.startswith("[AES-256-GCM]"):
            filename = header.split("]", 1)[1].strip()
            entry = {"method": "AES-256-GCM"}
            for line in lines[1:]:
                stripped = line.strip()
                if stripped.startswith("Key"):
                    entry["key"] = bytes.fromhex(stripped.split(":", 1)[1].strip().split()[0])
                elif stripped.startswith("Nonce"):
                    entry["nonce"] = bytes.fromhex(stripped.split(":", 1)[1].strip().split()[0])
                elif stripped.startswith("Tag"):
                    entry["tag"] = bytes.fromhex(stripped.split(":", 1)[1].strip().split()[0])
            keys[filename] = entry

        # --- SHA-256 ---
        elif header.startswith("[SHA-256]"):
            filename = header.split("]", 1)[1].strip()
            entry = {"method": "SHA-256"}
            for line in lines[1:]:
                if line.strip().startswith("Digest"):
                    entry["digest"] = line.split(":", 1)[1].strip()
            keys[filename] = entry

    return keys


# ---------------------------------------------------------------------------
# Decryption helpers
# ---------------------------------------------------------------------------

def decrypt_aes_cbc(ciphertext_with_iv: bytes, key: bytes) -> bytes:
    """Decrypt AES-CBC data where the first 16 bytes are the IV."""
    iv         = ciphertext_with_iv[:16]
    ciphertext = ciphertext_with_iv[16:]

    cipher    = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded    = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def decrypt_aes256_gcm(data: bytes, key: bytes, nonce: bytes, tag: bytes) -> bytes:
    """
    Decrypt AES-256-GCM data (nonce + tag + ciphertext layout).
    Raises cryptography.exceptions.InvalidTag if the file has been tampered with.
    """
    ciphertext = data[28:]  # skip nonce (12 B) + tag (16 B)
    cipher    = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

def decrypt_file(enc_path: str, keys: dict, verify_source: str = None) -> dict:
    """
    Decrypt *enc_path* using key material from *keys*.

    Looks up the filename in keys to determine the method — no file extension
    required. Output is written to a decrypted/ folder beside the input file.

    Returns a summary dict.
    Raises FileNotFoundError, KeyError, or ValueError on failure.
    """
    path = Path(enc_path)

    if not path.exists():
        raise FileNotFoundError(f"File not found: {enc_path}")
    if not path.is_file():
        raise ValueError(f"Not a regular file: {enc_path}")

    filename = path.name

    if filename not in keys:
        raise KeyError(
            f"No key entry found for '{filename}' in keys file.\n"
            f"  Make sure you are using the correct keys file for this encrypted output."
        )

    entry  = keys[filename]
    method = entry["method"]
    data   = path.read_bytes()

    decrypted_dir = path.parent.parent / "decrypted"
    decrypted_dir.mkdir(exist_ok=True)
    out_path = decrypted_dir / filename

    # --- SHA-256: verification only, cannot decrypt ---
    if method == "SHA-256":
        result = {"input": str(path), "method": "SHA-256 (verify only)", "output": None}

        if verify_source:
            src = Path(verify_source)
            if not src.exists():
                raise FileNotFoundError(f"Verify source not found: {verify_source}")
            actual_digest = hashlib.sha256(src.read_bytes()).hexdigest()
            match = actual_digest == entry["digest"]
            result["verified"] = match
            result["note"] = (
                "Digest matches — file is unmodified." if match
                else "DIGEST MISMATCH — file may have been altered!"
            )
        else:
            result["note"] = (
                "SHA-256 is a one-way hash; original content cannot be recovered.\n"
                "  To verify integrity, re-run with: --verify-only <original_file>"
            )
        return result

    # --- AES-CBC (128 or 192) ---
    if method in ("AES-128-CBC", "AES-192-CBC"):
        plaintext = decrypt_aes_cbc(data, entry["key"])

    # --- AES-256-GCM ---
    elif method == "AES-256-GCM":
        plaintext = decrypt_aes256_gcm(data, entry["key"], entry["nonce"], entry["tag"])

    else:
        raise ValueError(f"Unsupported method in keys file: {method}")

    out_path.write_bytes(plaintext)

    return {
        "input":     str(path),
        "output":    str(out_path),
        "method":    method,
        "in_bytes":  len(data),
        "out_bytes": len(plaintext),
    }


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------

def print_summary(results: list[dict]) -> None:
    print(f"\n{'='*65}")
    print(f"  DECRYPTION SUMMARY  ({len(results)} file(s) processed)")
    print(f"{'='*65}\n")

    for r in results:
        print(f"  File   : {r['input']}")
        print(f"  Method : {r['method']}")
        if r.get("output"):
            print(f"  Output : {r['output']}")
            print(f"  Size   : {r['in_bytes']} B  →  {r['out_bytes']} B")
        if r.get("note"):
            print(f"  Note   : {r['note']}")
        if "verified" in r:
            print(f"  Result : {'PASS' if r['verified'] else 'FAIL'}")
        print()

    print(f"{'='*65}\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Decrypt files produced by encryptor.py using key material from keys.txt. "
            "Pass the encrypted/ folder or individual files inside it."
        )
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="encrypted/ folder or individual encrypted files",
    )
    parser.add_argument(
        "--keys-in", "-k",
        default="keys.txt",
        help="Keys file to read from (default: keys.txt)",
    )
    parser.add_argument(
        "--verify-only",
        metavar="ORIGINAL",
        default=None,
        help="For SHA-256 entries: path to the original file to verify integrity against",
    )
    args = parser.parse_args()

    print(f"Loading keys from: {args.keys_in}")
    try:
        keys = parse_keys_file(args.keys_in)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"  {len(keys)} key entr{'y' if len(keys) == 1 else 'ies'} loaded.\n")

    # Collect target files
    targets = []
    for t in args.targets:
        if os.path.isdir(t):
            targets.extend(p for p in Path(t).iterdir() if p.is_file())
        elif os.path.isfile(t):
            targets.append(Path(t))
        else:
            print(f"  [SKIP] '{t}' is not a file or directory", file=sys.stderr)

    if not targets:
        print("No files found to process.")
        sys.exit(0)

    results = []
    errors  = []

    for target in targets:
        print(f"  [DECRYPT] {target}")
        try:
            result = decrypt_file(str(target), keys, verify_source=args.verify_only)
            results.append(result)
            label = result.get("output") or result.get("note", "")
            print(f"  [OK]      {target}  →  {label}")
        except (FileNotFoundError, KeyError, ValueError) as exc:
            errors.append((str(target), str(exc)))
            print(f"  [ERROR]   {target}: {exc}", file=sys.stderr)
        except Exception as exc:
            errors.append((str(target), str(exc)))
            print(f"  [ERROR]   {target}: {exc}", file=sys.stderr)

    if results:
        print_summary(results)

    if errors:
        print(f"\n{len(errors)} file(s) failed.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
