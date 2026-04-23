"""
AudioSteg – Advanced Audio Steganography Engine
================================================
Production-grade steganography engine with AES encryption, PBKDF2 key
derivation, SHA-256 integrity verification, and randomized LSB embedding.

Classes:
    - KeyDerivationManager: PBKDF2-based key and seed derivation
    - EncryptionManager: AES-128-CBC encryption via Fernet
    - IntegrityManager: SHA-256 hashing and verification
    - PayloadManager: Structured payload encoding with length-prefix
    - LSBEngine: LSB steganography with seeded PRNG positions
    - AudioProcessor: WAV file I/O and capacity analysis
"""

import os
import json
import wave
import struct
import hashlib
import logging
import base64
from typing import Tuple, Dict, Optional

import numpy as np
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("AudioSteg.Engine")


# ---------------------------------------------------------------------------
# KeyDerivationManager
# ---------------------------------------------------------------------------
class KeyDerivationManager:
    """Derives cryptographic keys from user passwords using PBKDF2-HMAC-SHA256.

    Two independent derivations share the same password:
      1. *Encryption key* – random salt stored in the payload so extraction
         can reconstruct the same key.
      2. *PRNG seed* – deterministic (fixed application salt) so embedding
         positions are reproducible from the password alone.
    """

    ITERATIONS: int = 480_000          # OWASP 2023 recommendation
    KEY_LENGTH: int = 32               # 256-bit key
    PRNG_SALT: bytes = b"AudioSteg::PRNG::SeedDerivation::v1"

    @staticmethod
    def derive_encryption_key(
        password: str,
        salt: Optional[bytes] = None,
    ) -> Tuple[bytes, bytes]:
        """Derive a Fernet-compatible encryption key from *password*.

        Parameters
        ----------
        password : str
            User-supplied passphrase.
        salt : bytes, optional
            16-byte salt.  Generated randomly when ``None`` (embedding);
            retrieved from the payload during extraction.

        Returns
        -------
        (key, salt) : Tuple[bytes, bytes]
            ``key`` is a 44-byte URL-safe-base64 string suitable for
            ``Fernet(key)``.
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KeyDerivationManager.KEY_LENGTH,
            salt=salt,
            iterations=KeyDerivationManager.ITERATIONS,
        )
        raw_key = kdf.derive(password.encode("utf-8"))
        fernet_key = base64.urlsafe_b64encode(raw_key)
        return fernet_key, salt

    @staticmethod
    def derive_prng_seed(password: str) -> int:
        """Derive a deterministic PRNG seed from *password*.

        Uses a fixed application salt so the seed is identical across
        embedding and extraction for the same password.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KeyDerivationManager.KEY_LENGTH,
            salt=KeyDerivationManager.PRNG_SALT,
            iterations=KeyDerivationManager.ITERATIONS,
        )
        seed_bytes = kdf.derive(password.encode("utf-8"))
        # Use first 4 bytes → positive 31-bit integer (NumPy constraint)
        return int.from_bytes(seed_bytes[:4], "big") % (2**31)


# ---------------------------------------------------------------------------
# EncryptionManager
# ---------------------------------------------------------------------------
class EncryptionManager:
    """AES-128-CBC encryption / decryption via the Fernet scheme.

    Fernet guarantees:
      • AES-CBC with PKCS7 padding
      • HMAC-SHA256 authentication
      • Timestamp-based token format
    """

    @staticmethod
    def encrypt(message: str, key: bytes) -> bytes:
        """Encrypt *message* and return Fernet token bytes."""
        f = Fernet(key)
        return f.encrypt(message.encode("utf-8"))

    @staticmethod
    def decrypt(token: bytes, key: bytes) -> str:
        """Decrypt a Fernet *token* and return the plaintext string.

        Raises ``cryptography.fernet.InvalidToken`` on failure.
        """
        f = Fernet(key)
        return f.decrypt(token).decode("utf-8")


# ---------------------------------------------------------------------------
# IntegrityManager
# ---------------------------------------------------------------------------
class IntegrityManager:
    """SHA-256 integrity hashing and verification."""

    @staticmethod
    def compute_hash(data: bytes) -> str:
        """Return the hex-encoded SHA-256 digest of *data*."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def verify_hash(data: bytes, expected_hash: str) -> bool:
        """Return ``True`` if the SHA-256 of *data* matches *expected_hash*."""
        return hashlib.sha256(data).hexdigest() == expected_hash


# ---------------------------------------------------------------------------
# PayloadManager
# ---------------------------------------------------------------------------
class PayloadManager:
    """Structured payload encoding with length-prefix framing.

    Wire format::

        ┌──────────────┬──────────────────────────────────────┐
        │ 4 bytes (BE) │  JSON payload (UTF-8)                │
        │ payload len  │  {"salt":"…","data":"…","hash":"…"}  │
        └──────────────┴──────────────────────────────────────┘

    The 4-byte big-endian length prefix encodes the size of the JSON
    payload **only** (not including the prefix itself).
    """

    LENGTH_PREFIX_SIZE: int = 4   # bytes

    @staticmethod
    def encode(encrypted_token: bytes, salt: bytes) -> bytes:
        """Build a length-prefixed binary payload.

        Parameters
        ----------
        encrypted_token : bytes
            Fernet token (already URL-safe-base64).
        salt : bytes
            The random salt used for PBKDF2 key derivation.

        Returns
        -------
        bytes
            ``length_prefix ‖ json_payload``
        """
        payload_dict = {
            "salt": base64.b64encode(salt).decode("ascii"),
            "data": encrypted_token.decode("ascii"),
            "hash": IntegrityManager.compute_hash(encrypted_token),
        }
        json_bytes = json.dumps(payload_dict, separators=(",", ":")).encode("utf-8")
        length_prefix = struct.pack(">I", len(json_bytes))
        return length_prefix + json_bytes

    @staticmethod
    def decode(raw: bytes) -> dict:
        """Decode a length-prefixed structured payload.

        Parameters
        ----------
        raw : bytes
            Must begin with a 4-byte big-endian length prefix followed by
            at least that many bytes of JSON.

        Returns
        -------
        dict
            Parsed payload with keys ``salt``, ``data``, ``hash``.
        """
        pfx = PayloadManager.LENGTH_PREFIX_SIZE
        if len(raw) < pfx:
            raise ValueError("Payload too short to contain length prefix")

        json_len = struct.unpack(">I", raw[:pfx])[0]
        if json_len == 0 or json_len > 50_000_000:
            raise ValueError(
                "Invalid payload length — likely wrong password or no hidden data"
            )
        if pfx + json_len > len(raw):
            raise ValueError("Payload truncated — data may be corrupted")

        try:
            payload = json.loads(raw[pfx : pfx + json_len].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ValueError(f"Malformed payload JSON: {exc}") from exc

        required = {"salt", "data", "hash"}
        if not required.issubset(payload.keys()):
            missing = required - payload.keys()
            raise ValueError(f"Payload missing required fields: {missing}")

        return payload


# ---------------------------------------------------------------------------
# Steg Engines
# ---------------------------------------------------------------------------

class RandomLSBEngine:
    """Least-Significant-Bit embedding / extraction with seeded PRNG.

    Embedding positions are determined by a pseudo-random permutation of
    all sample indices, seeded by a password-derived value.  This means
    bits are **not** written to consecutive samples — an attacker cannot
    simply read the first *N* LSBs to recover the message.
    """

    @staticmethod
    def _get_permutation(seed: int, num_samples: int) -> np.ndarray:
        """Return a full permutation of ``[0, num_samples)``."""
        rng = np.random.RandomState(seed)
        return rng.permutation(np.arange(num_samples, dtype=np.int32))

    @staticmethod
    def embed(samples: np.ndarray, data: bytes, seed: int) -> np.ndarray:
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        num_bits = len(bits)

        if num_bits > len(samples):
            raise ValueError(
                f"Payload too large: needs {num_bits} bits but only "
                f"{len(samples)} sample slots available"
            )

        positions = RandomLSBEngine._get_permutation(seed, len(samples))[:num_bits]

        modified = samples.copy()
        mask = np.int16(-2)  # 0xFFFE — clears the LSB
        modified[positions] = (modified[positions] & mask) | bits.astype(np.int16)

        logger.info(
            "Random LSB embed: %d bits into %d samples (%.2f%% used)",
            num_bits,
            len(samples),
            num_bits / len(samples) * 100,
        )
        return modified

    @staticmethod
    def extract(samples: np.ndarray, seed: int) -> bytes:
        num_samples = len(samples)
        if num_samples < 32:
            raise ValueError("Audio file too short for extraction")

        positions = RandomLSBEngine._get_permutation(seed, num_samples)

        # Phase 1 — read length prefix (32 bits = 4 bytes) ..................
        prefix_bits = (samples[positions[:32]] & 1).astype(np.uint8)
        prefix_bytes = np.packbits(prefix_bits).tobytes()
        json_len = struct.unpack(">I", prefix_bytes)[0]

        # Sanity guards
        if json_len == 0 or json_len > 50_000_000:
            raise ValueError(
                "Extracted length prefix is invalid — wrong password or "
                "file does not contain hidden data"
            )

        total_bits = 32 + json_len * 8
        if total_bits > num_samples:
            raise ValueError(
                f"Payload claims {json_len} bytes but audio only has "
                f"{num_samples} samples — data corrupted or wrong password"
            )

        # Phase 2 — read JSON payload .......................................
        payload_bits = (samples[positions[32:total_bits]] & 1).astype(np.uint8)
        payload_bytes = np.packbits(payload_bits).tobytes()[:json_len]

        logger.info(
            "Random LSB extract: %d payload bytes from %d samples", json_len, num_samples
        )
        return prefix_bytes + payload_bytes


class SequentialLSBEngine:
    """Least-Significant-Bit embedding / extraction in sequential order.
    
    Easier to detect statistically, but faster and deterministic.
    """

    @staticmethod
    def embed(samples: np.ndarray, data: bytes, seed: int) -> np.ndarray:
        # Seed is ignored for sequential embedding
        bits = np.unpackbits(np.frombuffer(data, dtype=np.uint8))
        num_bits = len(bits)

        if num_bits > len(samples):
            raise ValueError(
                f"Payload too large: needs {num_bits} bits but only "
                f"{len(samples)} sample slots available"
            )

        modified = samples.copy()
        mask = np.int16(-2)  # 0xFFFE — clears the LSB
        modified[:num_bits] = (modified[:num_bits] & mask) | bits.astype(np.int16)

        logger.info(
            "Sequential LSB embed: %d bits into %d samples (%.2f%% used)",
            num_bits,
            len(samples),
            num_bits / len(samples) * 100,
        )
        return modified

    @staticmethod
    def extract(samples: np.ndarray, seed: int) -> bytes:
        num_samples = len(samples)
        if num_samples < 32:
            raise ValueError("Audio file too short for extraction")

        # Phase 1 — read length prefix (32 bits = 4 bytes)
        prefix_bits = (samples[:32] & 1).astype(np.uint8)
        prefix_bytes = np.packbits(prefix_bits).tobytes()
        json_len = struct.unpack(">I", prefix_bytes)[0]

        # Sanity guards
        if json_len == 0 or json_len > 50_000_000:
            raise ValueError(
                "Extracted length prefix is invalid — wrong password or "
                "file does not contain hidden data"
            )

        total_bits = 32 + json_len * 8
        if total_bits > num_samples:
            raise ValueError(
                f"Payload claims {json_len} bytes but audio only has "
                f"{num_samples} samples — data corrupted or wrong password"
            )

        # Phase 2 — read JSON payload
        payload_bits = (samples[32:total_bits] & 1).astype(np.uint8)
        payload_bytes = np.packbits(payload_bits).tobytes()[:json_len]

        logger.info(
            "Sequential LSB extract: %d payload bytes from %d samples", json_len, num_samples
        )
        return prefix_bytes + payload_bytes


class MetadataEngine:
    """Metadata-based embedding using a custom RIFF chunk.
    
    This does not alter audio samples. It appends a custom 'steg' chunk
    to the WAV file structure. It is less stealthy to forensic tools,
    but completely preserves audio fidelity.
    """
    
    CHUNK_ID = b"steg"

    @staticmethod
    def embed(filepath: str, data: bytes) -> None:
        """Append a custom RIFF chunk to the WAV file."""
        with open(filepath, "r+b") as f:
            f.seek(0)
            header = f.read(12)
            if len(header) < 12 or header[:4] != b"RIFF" or header[8:12] != b"WAVE":
                raise ValueError("Not a valid WAV file for metadata embedding")
            
            # Read existing main RIFF size
            riff_size = struct.unpack("<I", header[4:8])[0]
            
            # Prepare our chunk: ID (4) + Size (4, LE) + Data + Pad byte if odd
            chunk_size = len(data)
            pad = b"\\x00" if chunk_size % 2 != 0 else b""
            chunk_header = MetadataEngine.CHUNK_ID + struct.pack("<I", chunk_size)
            steg_chunk = chunk_header + data + pad
            
            # Append to file
            f.seek(0, 2)
            f.write(steg_chunk)
            
            # Update RIFF size to include our new chunk
            new_riff_size = riff_size + len(steg_chunk)
            f.seek(4)
            f.write(struct.pack("<I", new_riff_size))
            
        logger.info("Metadata embed: %d bytes into custom RIFF chunk", len(data))

    @staticmethod
    def extract(filepath: str) -> bytes:
        """Extract the payload from the custom RIFF chunk."""
        with open(filepath, "rb") as f:
            header = f.read(12)
            if len(header) < 12 or header[:4] != b"RIFF" or header[8:12] != b"WAVE":
                raise ValueError("Not a valid WAV file")
            
            while True:
                chunk_id = f.read(4)
                if not chunk_id or len(chunk_id) < 4:
                    break
                
                size_data = f.read(4)
                if not size_data or len(size_data) < 4:
                    break
                
                chunk_size = struct.unpack("<I", size_data)[0]
                
                if chunk_id == MetadataEngine.CHUNK_ID:
                    data = f.read(chunk_size)
                    logger.info("Metadata extract: found %d bytes in custom chunk", len(data))
                    return data
                else:
                    # Skip to next chunk (respecting padding)
                    f.seek(chunk_size + (chunk_size % 2), 1)
                    
        raise ValueError("No steganography chunk found in metadata")


# ---------------------------------------------------------------------------
# AudioProcessor
# ---------------------------------------------------------------------------
class AudioProcessor:
    """WAV audio file I/O and capacity analysis.

    Only 16-bit (``int16``) PCM WAV files are supported — this is the
    standard format for CD-quality audio and PyInstaller-friendly
    processing.
    """

    SUPPORTED_SAMPLE_WIDTH = 2  # bytes (16-bit)

    @staticmethod
    def read_wav(filepath: str) -> Tuple[np.ndarray, Dict]:
        """Read a 16-bit WAV and return ``(samples, params)``.

        ``params`` is a dict with keys: ``nchannels``, ``sampwidth``,
        ``framerate``, ``nframes``.
        """
        try:
            with wave.open(filepath, "rb") as wf:
                params = {
                    "nchannels": wf.getnchannels(),
                    "sampwidth": wf.getsampwidth(),
                    "framerate": wf.getframerate(),
                    "nframes": wf.getnframes(),
                }
                if params["sampwidth"] != AudioProcessor.SUPPORTED_SAMPLE_WIDTH:
                    raise ValueError(
                        f"Unsupported sample width: {params['sampwidth'] * 8}-bit. "
                        f"Only 16-bit PCM WAV files are accepted."
                    )
                raw = wf.readframes(params["nframes"])
                samples = np.frombuffer(raw, dtype=np.int16).copy()
                logger.info(
                    "Read WAV: %s — %d channels, %d Hz, %d frames, %d samples",
                    filepath,
                    params["nchannels"],
                    params["framerate"],
                    params["nframes"],
                    len(samples),
                )
                return samples, params
        except wave.Error as exc:
            raise ValueError(f"Cannot read WAV file: {exc}") from exc

    @staticmethod
    def write_wav(filepath: str, samples: np.ndarray, params: Dict) -> None:
        """Write *samples* to a WAV file preserving original *params*."""
        with wave.open(filepath, "wb") as wf:
            wf.setnchannels(params["nchannels"])
            wf.setsampwidth(params["sampwidth"])
            wf.setframerate(params["framerate"])
            wf.writeframes(samples.tobytes())
        logger.info("Wrote WAV: %s (%d samples)", filepath, len(samples))

    @staticmethod
    def compute_capacity(num_samples: int) -> Dict:
        """Estimate embedding capacity for an audio buffer.

        Returns a dict with:
          - ``total_samples`` – raw sample count
          - ``max_payload_bytes`` – maximum embeddable byte count
          - ``max_message_chars`` – estimated plaintext character limit
        """
        max_payload_bytes = num_samples // 8

        # Overhead breakdown (approximate):
        #   Length prefix:       4  bytes
        #   JSON structure:     30  bytes  {"salt":"","data":"","hash":""}
        #   Salt (base64):      24  bytes
        #   SHA-256 hash:       64  bytes
        #   ─────────────────────────────
        #   Fixed overhead:    ~122 bytes
        #
        # Fernet token ≈ (message_len + 73) * 4/3  (base64 of AES-CBC + HMAC)
        fixed_overhead = 122 + PayloadManager.LENGTH_PREFIX_SIZE
        available_for_token = max(0, max_payload_bytes - fixed_overhead)
        # Fernet token → raw encrypted: available * 3/4
        available_raw = int(available_for_token * 3 / 4)
        # Fernet raw overhead (version + timestamp + IV + HMAC + 1-block padding): ~73 bytes
        fernet_overhead = 73
        max_message_chars = max(0, available_raw - fernet_overhead)

        return {
            "total_samples": num_samples,
            "max_payload_bytes": max_payload_bytes,
            "max_message_chars": max_message_chars,
        }
