"""End-to-end round-trip test for AudioSteg engine."""
import sys, os, base64
sys.path.insert(0, os.path.dirname(__file__))

from steg_engine import (
    KeyDerivationManager, EncryptionManager, IntegrityManager,
    PayloadManager, LSBEngine, AudioProcessor,
)

AUDIO = os.path.join(os.path.dirname(__file__), "test_audio.wav")
OUTPUT = os.path.join(os.path.dirname(__file__), "test_stego.wav")
PASSWORD = "MySecureP@ss123"
MESSAGE = "Hello, this is a TOP SECRET message embedded via AudioSteg! 🔐"

def test():
    print("=" * 60)
    print("AUDIOSTEG — Round-Trip Test")
    print("=" * 60)

    # 1. Read audio
    samples, params = AudioProcessor.read_wav(AUDIO)
    print(f"[1] Read audio: {len(samples)} samples, {params['framerate']} Hz")

    # 2. Capacity
    cap = AudioProcessor.compute_capacity(len(samples))
    print(f"[2] Capacity: {cap['max_payload_bytes']} bytes, ~{cap['max_message_chars']} chars")

    # 3. Derive keys
    enc_key, salt = KeyDerivationManager.derive_encryption_key(PASSWORD)
    prng_seed = KeyDerivationManager.derive_prng_seed(PASSWORD)
    print(f"[3] Keys derived (salt={salt.hex()[:16]}…, seed={prng_seed})")

    # 4. Encrypt
    token = EncryptionManager.encrypt(MESSAGE, enc_key)
    print(f"[4] Encrypted: {len(token)} bytes token")

    # 5. Build payload
    payload = PayloadManager.encode(token, salt)
    print(f"[5] Payload: {len(payload)} bytes ({len(payload)*8} bits)")

    # 6. Capacity check
    if len(payload) * 8 > len(samples):
        print("[!] FAIL: Message too large for audio!")
        return False

    usage = len(payload) * 8 / len(samples) * 100
    print(f"[6] Capacity used: {usage:.2f}%")

    # 7. Embed
    modified = LSBEngine.embed(samples, payload, prng_seed)
    print(f"[7] Embedded into {len(modified)} samples")

    # 8. Write stego file
    AudioProcessor.write_wav(OUTPUT, modified, params)
    print(f"[8] Wrote stego file: {OUTPUT}")

    # ─── Extraction ───
    print("\n--- EXTRACTION ---")

    # 9. Read stego
    stego_samples, stego_params = AudioProcessor.read_wav(OUTPUT)
    print(f"[9] Read stego: {len(stego_samples)} samples")

    # 10. Derive same PRNG seed
    prng_seed2 = KeyDerivationManager.derive_prng_seed(PASSWORD)
    assert prng_seed2 == prng_seed, "PRNG seeds don't match!"
    print(f"[10] PRNG seed matches: {prng_seed2}")

    # 11. Extract
    raw = LSBEngine.extract(stego_samples, prng_seed2)
    print(f"[11] Extracted: {len(raw)} raw bytes")

    # 12. Decode payload
    decoded = PayloadManager.decode(raw)
    print(f"[12] Decoded payload: keys={list(decoded.keys())}")

    # 13. Integrity check
    enc_token = decoded["data"].encode("ascii")
    ok = IntegrityManager.verify_hash(enc_token, decoded["hash"])
    print(f"[13] Integrity: {'✓ PASS' if ok else '✗ FAIL'}")
    assert ok, "Integrity check failed!"

    # 14. Derive encryption key with stored salt
    stored_salt = base64.b64decode(decoded["salt"])
    enc_key2, _ = KeyDerivationManager.derive_encryption_key(PASSWORD, stored_salt)
    print(f"[14] Encryption key re-derived")

    # 15. Decrypt
    decrypted = EncryptionManager.decrypt(enc_token, enc_key2)
    print(f"[15] Decrypted: '{decrypted}'")

    # 16. Verify
    match = decrypted == MESSAGE
    print(f"\n{'='*60}")
    print(f"RESULT: {'✓ ALL TESTS PASSED' if match else '✗ MISMATCH'}")
    print(f"  Original:  '{MESSAGE}'")
    print(f"  Extracted: '{decrypted}'")
    print(f"{'='*60}")

    # Cleanup
    os.remove(OUTPUT)
    return match

if __name__ == "__main__":
    success = test()
    sys.exit(0 if success else 1)
