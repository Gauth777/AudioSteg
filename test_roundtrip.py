"""End-to-end round-trip test for AudioSteg engines."""
import sys, os, base64
sys.path.insert(0, os.path.dirname(__file__))

from steg_engine import (
    KeyDerivationManager, EncryptionManager, IntegrityManager,
    PayloadManager, RandomLSBEngine, SequentialLSBEngine, MetadataEngine, AudioProcessor,
)

AUDIO = os.path.join(os.path.dirname(__file__), "test_audio.wav")
PASSWORD = "MySecureP@ss123"
MESSAGE = "Hello, this is a TOP SECRET message embedded via AudioSteg! 🔐"

def test_algorithm(algorithm_name, embed_class, extract_class, is_metadata=False):
    output_wav = os.path.join(os.path.dirname(__file__), f"test_stego_{algorithm_name}.wav")
    print(f"\n{'=' * 60}")
    print(f"TESTING ALGORITHM: {algorithm_name}")
    print(f"{'=' * 60}")

    # 1. Read audio
    samples, params = AudioProcessor.read_wav(AUDIO)
    print(f"[1] Read audio: {len(samples)} samples")

    # 2. Derive keys
    enc_key, salt = KeyDerivationManager.derive_encryption_key(PASSWORD)
    prng_seed = KeyDerivationManager.derive_prng_seed(PASSWORD)
    print(f"[2] Keys derived")

    # 3. Encrypt
    token = EncryptionManager.encrypt(MESSAGE, enc_key)

    # 4. Build payload
    payload = PayloadManager.encode(token, salt)
    print(f"[3] Payload: {len(payload)} bytes")

    # 5. Embed
    if is_metadata:
        AudioProcessor.write_wav(output_wav, samples, params)
        embed_class.embed(output_wav, payload)
        print(f"[4] Embedded into {output_wav} using Metadata Chunk")
    else:
        modified = embed_class.embed(samples, payload, prng_seed)
        AudioProcessor.write_wav(output_wav, modified, params)
        print(f"[4] Embedded into {len(modified)} samples")

    # ─── Extraction ───
    print("--- EXTRACTION ---")

    # 6. Extract
    prng_seed2 = KeyDerivationManager.derive_prng_seed(PASSWORD)
    if is_metadata:
        raw = extract_class.extract(output_wav)
    else:
        stego_samples, _ = AudioProcessor.read_wav(output_wav)
        raw = extract_class.extract(stego_samples, prng_seed2)
        
    print(f"[5] Extracted: {len(raw)} raw bytes")

    # 7. Decode payload
    decoded = PayloadManager.decode(raw)

    # 8. Integrity check
    enc_token = decoded["data"].encode("ascii")
    ok = IntegrityManager.verify_hash(enc_token, decoded["hash"])
    print(f"[6] Integrity: {'PASS' if ok else 'FAIL'}")
    if not ok: return False

    # 9. Decrypt
    stored_salt = base64.b64decode(decoded["salt"])
    enc_key2, _ = KeyDerivationManager.derive_encryption_key(PASSWORD, stored_salt)
    decrypted = EncryptionManager.decrypt(enc_token, enc_key2)

    # 10. Verify
    match = decrypted == MESSAGE
    print(f"RESULT: {'PASS' if match else 'FAIL'}")
    
    if os.path.exists(output_wav):
        os.remove(output_wav)
        
    return match

def test():
    results = []
    results.append(test_algorithm("RandomLSB", RandomLSBEngine, RandomLSBEngine, is_metadata=False))
    results.append(test_algorithm("SequentialLSB", SequentialLSBEngine, SequentialLSBEngine, is_metadata=False))
    results.append(test_algorithm("MetadataChunk", MetadataEngine, MetadataEngine, is_metadata=True))
    
    print(f"\n{'=' * 60}")
    if all(results):
        print("ALL TESTS PASSED")
        return True
    else:
        print("SOME TESTS FAILED")
        return False

if __name__ == "__main__":
    success = test()
    sys.exit(0 if success else 1)
