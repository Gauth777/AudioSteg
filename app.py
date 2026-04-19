"""
AudioSteg – Flask Application Server
=====================================
Launches a local Flask server and auto-opens the browser.
Provides REST API endpoints for embedding, extraction, capacity
analysis, and stego-file download.

Usage:
    python app.py          — starts server on http://127.0.0.1:5000
    pyinstaller app.spec   — builds standalone .exe
"""

import os
import sys
import uuid
import base64
import logging
import tempfile
import webbrowser
import threading

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    send_file,
)
from werkzeug.utils import secure_filename
from cryptography.fernet import InvalidToken

from steg_engine import (
    KeyDerivationManager,
    EncryptionManager,
    IntegrityManager,
    PayloadManager,
    LSBEngine,
    AudioProcessor,
)


# ---------------------------------------------------------------------------
# Resource path helper (PyInstaller-compatible)
# ---------------------------------------------------------------------------
def resource_path(relative_path: str) -> str:
    """Resolve path to a bundled resource (works with PyInstaller)."""
    if hasattr(sys, "_MEIPASS"):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "activity.log"
)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
# Also log to console
console_handler = logging.StreamHandler(sys.stdout)
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
)
logging.getLogger().addHandler(console_handler)

logger = logging.getLogger("AudioSteg.App")


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------
app = Flask(
    __name__,
    template_folder=resource_path("templates"),
    static_folder=resource_path("static"),
)
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024  # 100 MB upload limit

UPLOAD_DIR = tempfile.mkdtemp(prefix="audiosteg_")
ALLOWED_EXTENSIONS = {".wav"}


def _allowed(filename: str) -> bool:
    return os.path.splitext(filename)[1].lower() in ALLOWED_EXTENSIONS


def _save_upload(file_storage) -> str:
    """Save an uploaded file to the temp dir and return its path."""
    safe_name = secure_filename(file_storage.filename) or "upload.wav"
    path = os.path.join(UPLOAD_DIR, f"{uuid.uuid4().hex[:8]}_{safe_name}")
    file_storage.save(path)
    return path


def _cleanup(path: str) -> None:
    """Silently remove a temp file."""
    try:
        if path and os.path.isfile(path):
            os.remove(path)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serve the single-page UI."""
    return render_template("index.html")


# -- Capacity ---------------------------------------------------------------

@app.route("/api/capacity", methods=["POST"])
def api_capacity():
    """Analyse a WAV file and return embedding capacity."""
    if "audio" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    f = request.files["audio"]
    if not _allowed(f.filename):
        return jsonify({"error": "Only .wav files are supported"}), 400

    path = _save_upload(f)
    try:
        samples, params = AudioProcessor.read_wav(path)
        capacity = AudioProcessor.compute_capacity(len(samples))
        duration = params["nframes"] / params["framerate"]
        logger.info(
            "Capacity check: %s — %d samples, ~%d chars capacity",
            f.filename,
            len(samples),
            capacity["max_message_chars"],
        )
        return jsonify({
            "capacity": capacity,
            "duration": round(duration, 2),
            "channels": params["nchannels"],
            "sample_rate": params["framerate"],
            "filename": f.filename,
        })
    except Exception as exc:
        logger.error("Capacity check failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    finally:
        _cleanup(path)


# -- Embed ------------------------------------------------------------------

@app.route("/api/embed", methods=["POST"])
def api_embed():
    """Embed an encrypted message into a WAV file."""
    # --- Validate inputs ---
    if "audio" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    f = request.files["audio"]
    message = request.form.get("message", "").strip()
    password = request.form.get("password", "").strip()

    if not message:
        return jsonify({"error": "Message cannot be empty"}), 400
    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if not _allowed(f.filename):
        return jsonify({"error": "Only .wav files are supported"}), 400

    path = _save_upload(f)
    output_path = None
    try:
        # 1. Read audio
        samples, params = AudioProcessor.read_wav(path)
        logger.info("Embed: loaded %s (%d samples)", f.filename, len(samples))

        # 2. Derive keys
        encryption_key, salt = KeyDerivationManager.derive_encryption_key(password)
        prng_seed = KeyDerivationManager.derive_prng_seed(password)

        # 3. Encrypt
        encrypted_token = EncryptionManager.encrypt(message, encryption_key)
        logger.info("Embed: encrypted (%d bytes token)", len(encrypted_token))

        # 4. Build payload
        payload = PayloadManager.encode(encrypted_token, salt)
        payload_bits = len(payload) * 8
        logger.info("Embed: payload = %d bytes (%d bits)", len(payload), payload_bits)

        # 5. Capacity check
        if payload_bits > len(samples):
            capacity = AudioProcessor.compute_capacity(len(samples))
            raise ValueError(
                f"Message too large. Payload needs {len(payload)} bytes "
                f"but audio can hold at most {capacity['max_payload_bytes']} bytes. "
                f"Use a longer audio file or a shorter message."
            )

        # 6. Embed
        modified = LSBEngine.embed(samples, payload, prng_seed)

        # 7. Write output
        out_name = f"stego_{uuid.uuid4().hex[:8]}.wav"
        output_path = os.path.join(UPLOAD_DIR, out_name)
        AudioProcessor.write_wav(output_path, modified, params)

        usage_pct = round(payload_bits / len(samples) * 100, 2)
        logger.info("Embed: success — %.2f%% capacity used", usage_pct)

        return jsonify({
            "success": True,
            "download_filename": out_name,
            "payload_bytes": len(payload),
            "payload_bits": payload_bits,
            "total_samples": len(samples),
            "usage_percent": usage_pct,
            "message_length": len(message),
        })

    except Exception as exc:
        logger.error("Embed failed: %s", exc)
        return jsonify({"error": str(exc)}), 400
    finally:
        _cleanup(path)


# -- Extract ----------------------------------------------------------------

@app.route("/api/extract", methods=["POST"])
def api_extract():
    """Extract and decrypt a hidden message from a stego WAV file."""
    if "audio" not in request.files:
        return jsonify({"error": "No audio file provided"}), 400

    f = request.files["audio"]
    password = request.form.get("password", "").strip()

    if not password:
        return jsonify({"error": "Password cannot be empty"}), 400
    if not _allowed(f.filename):
        return jsonify({"error": "Only .wav files are supported"}), 400

    path = _save_upload(f)
    try:
        # 1. Read audio
        samples, params = AudioProcessor.read_wav(path)
        logger.info("Extract: loaded %s (%d samples)", f.filename, len(samples))

        # 2. Derive PRNG seed (for position reconstruction)
        prng_seed = KeyDerivationManager.derive_prng_seed(password)

        # 3. Extract raw payload
        raw = LSBEngine.extract(samples, prng_seed)
        logger.info("Extract: raw payload = %d bytes", len(raw))

        # 4. Decode structured payload
        payload = PayloadManager.decode(raw)

        # 5. Integrity verification
        encrypted_token = payload["data"].encode("ascii")
        expected_hash = payload["hash"]

        if not IntegrityManager.verify_hash(encrypted_token, expected_hash):
            raise ValueError(
                "Integrity verification failed — data has been tampered with "
                "or the wrong password was used"
            )
        logger.info("Extract: SHA-256 integrity check PASSED")

        # 6. Derive encryption key (with stored salt)
        salt = base64.b64decode(payload["salt"])
        encryption_key, _ = KeyDerivationManager.derive_encryption_key(password, salt)

        # 7. Decrypt
        message = EncryptionManager.decrypt(encrypted_token, encryption_key)
        logger.info("Extract: decrypted message (%d chars)", len(message))

        return jsonify({
            "success": True,
            "message": message,
            "message_length": len(message),
            "integrity_verified": True,
        })

    except InvalidToken:
        logger.error("Extract: Fernet decryption failed (wrong password)")
        return jsonify({
            "error": "Decryption failed — incorrect password or corrupted data"
        }), 400
    except Exception as exc:
        logger.error("Extract failed: %s", exc)
        error_msg = str(exc)
        # Provide user-friendly messages
        if "InvalidToken" in error_msg:
            error_msg = "Decryption failed — incorrect password or corrupted data"
        return jsonify({"error": error_msg}), 400
    finally:
        _cleanup(path)


# -- Download ---------------------------------------------------------------

@app.route("/api/download/<filename>")
def api_download(filename):
    """Serve a stego WAV file for download."""
    safe = secure_filename(filename)
    path = os.path.join(UPLOAD_DIR, safe)
    if not os.path.isfile(path):
        return jsonify({"error": "File not found — it may have expired"}), 404

    logger.info("Download: %s", safe)
    return send_file(path, as_attachment=True, download_name=safe)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def _open_browser(port: int) -> None:
    """Open the default browser after a short delay."""
    webbrowser.open(f"http://127.0.0.1:{port}")


if __name__ == "__main__":
    PORT = 5000
    logger.info("=" * 60)
    logger.info("AudioSteg server starting on http://127.0.0.1:%d", PORT)
    logger.info("Upload directory: %s", UPLOAD_DIR)
    logger.info("=" * 60)

    # Auto-open browser after Flask is ready
    threading.Timer(1.5, _open_browser, args=[PORT]).start()

    app.run(host="127.0.0.1", port=PORT, debug=False)
