# AudioSteg — Advanced Audio Steganography

**Production-grade desktop tool** for embedding and extracting AES-encrypted
messages within WAV audio files using LSB steganography.


---

## Features

| Feature                | Description                                                    |
|------------------------|----------------------------------------------------------------|
| **AES Encryption**     | Fernet (AES-128-CBC + HMAC-SHA256) via `cryptography`          |
| **PBKDF2 Key Derivation** | 480 000 iterations of PBKDF2-HMAC-SHA256                    |
| **Randomised LSB**     | Password-seeded PRNG determines embedding positions            |
| **Structured Payload** | Length-prefixed JSON with `{salt, data, hash}`                 |
| **Integrity Check**    | SHA-256 hash verified on extraction                            |
| **Capacity Analysis**  | Real-time payload vs capacity visualisation                    |
| **Activity Logging**   | All operations logged to `activity.log`                        |
| **Dark Cyber UI**      | Glassmorphism, neon accents, animated grid background          |
| **PyInstaller Ready**  | Bundle as a standalone `.exe`                                  |

---

## Project Structure

```
AudioSteg/
├── app.py              # Flask server + REST API
├── steg_engine.py      # Core engine (6 modular classes)
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
| `LSBEngine`             | Randomised LSB embed / extract                  |
| `AudioProcessor`        | WAV read / write / capacity analysis             |

---

## Building a Standalone `.exe`

```bash
pip install pyinstaller
pyinstaller --onefile --add-data "templates;templates" --add-data "static;static" --name AudioSteg --icon=NONE app.py
```

The executable will be in `dist/AudioSteg.exe`.

> **Note:** On first run, Windows Defender may briefly scan the new `.exe`.
> The `resource_path()` helper in `app.py` ensures templates and static files
> are correctly resolved when running from a PyInstaller bundle.

---

## API Endpoints

| Method | Endpoint               | Description                        |
|--------|------------------------|------------------------------------|
| GET    | `/`                    | Serve the UI                       |
| POST   | `/api/capacity`        | Analyse WAV capacity               |
| POST   | `/api/embed`           | Embed encrypted message            |
| POST   | `/api/extract`         | Extract and decrypt message        |
| GET    | `/api/download/<file>` | Download stego WAV                 |

---

## Security Notes

- Encryption keys are **never stored** — derived at runtime from the password.
- A random 16-byte salt is generated per embedding and stored inside the
  payload, ensuring unique ciphertext even for identical messages.
- The PRNG seed uses a separate fixed salt, so embedding positions are
  deterministic per password but independent of the encryption salt.
- PBKDF2 with 480 000 iterations provides strong resistance against brute-force
  attacks (OWASP 2023 recommendation).

