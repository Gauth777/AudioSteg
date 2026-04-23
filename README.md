# AudioSteg — Advanced Audio Steganography

**Production-grade desktop tool** for embedding and extracting AES-encrypted
messages within WAV audio files using multiple steganography algorithms.


---

## Features

| Feature                | Description                                                    |
|------------------------|----------------------------------------------------------------|
| **Multi-Algorithm**    | Choose between Randomized LSB, Sequential LSB, and Metadata Chunk embedding. |
| **AES Encryption**     | Fernet (AES-128-CBC + HMAC-SHA256) via `cryptography`          |
| **PBKDF2 Key Derivation** | 480 000 iterations of PBKDF2-HMAC-SHA256                    |
| **Steganalysis**       | Audio analysis module to detect LSB ratio anomalies, chi-square deviations, and metadata tampering. |
| **Structured Payload** | Length-prefixed JSON with `{salt, data, hash}`                 |
| **Integrity Check**    | SHA-256 hash verified on extraction                            |
| **Capacity Analysis**  | Real-time payload vs capacity visualisation                    |
| **Automated Reports**  | JSON reports generated for embedding, extraction, and analysis.|
| **Dark Cyber UI**      | Glassmorphism, neon accents, animated grid background          |
| **PyInstaller Ready**  | Bundle as a standalone `.exe` using the included `build.py` script. |

---

## Project Structure

```
AudioSteg/
├── app.py              # Flask server + REST API
├── steg_engine.py      # Core engine (Strategy-based steganography engines)
├── analysis.py         # Steganalysis and anomaly detection
├── build.py            # PyInstaller build script
├── requirements.txt    # Python dependencies
├── activity.log        # Auto-generated operation log
├── templates/
│   └── index.html      # Single-page UI
└── static/
    ├── style.css       # Dark cybersecurity theme
    └── script.js       # Frontend controller
```

### Engine Classes

| Class                   | Responsibility                                  |
|-------------------------|-------------------------------------------------|
| `KeyDerivationManager`  | PBKDF2 key + PRNG seed derivation               |
| `EncryptionManager`     | Fernet encrypt / decrypt                        |
| `IntegrityManager`      | SHA-256 hash + verify                           |
| `PayloadManager`        | JSON payload encode / decode with length prefix  |
| `RandomLSBEngine`       | Randomised LSB embed / extract (High Stealth)   |
| `SequentialLSBEngine`   | Sequential LSB embed / extract (Low Stealth)    |
| `MetadataEngine`        | Custom RIFF Chunk embed / extract               |
| `AudioProcessor`        | WAV read / write / capacity analysis             |
| `AudioAnalyzer`         | Statistical and structural analysis             |

---

## API Endpoints

| Method | Endpoint               | Description                        |
|--------|------------------------|------------------------------------|
| GET    | `/`                    | Serve the UI                       |
| POST   | `/api/capacity`        | Analyse WAV capacity               |
| POST   | `/api/embed`           | Embed encrypted message            |
| POST   | `/api/extract`         | Extract and decrypt message        |
| POST   | `/api/analyze`         | Analyse audio for steganography    |
| GET    | `/api/download/<file>` | Download stego WAV                 |
| GET    | `/api/report/<file>`   | Download JSON operation report     |

---

## Security Notes

- Encryption keys are **never stored** — derived at runtime from the password.
- A random 16-byte salt is generated per embedding and stored inside the
  payload, ensuring unique ciphertext even for identical messages.
- The PRNG seed uses a separate fixed salt, so embedding positions are
  deterministic per password but independent of the encryption salt.
- PBKDF2 with 480 000 iterations provides strong resistance against brute-force
  attacks (OWASP 2023 recommendation).
