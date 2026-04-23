/**
 * AudioSteg — Frontend Controller
 * =================================
 * Handles file uploads, capacity analysis, embed/extract API calls,
 * UI state management, and real-time capacity visualisation.
 */

(function () {
    "use strict";

    /* ─── DOM refs ────────────────────────────────────────────── */
    const $ = (sel) => document.querySelector(sel);

    // Embed
    const embedFile       = $("#embed-file");
    const embedDropZone   = $("#embed-drop-zone");
    const embedFilePrompt = $("#embed-file-prompt");
    const embedFileInfo   = $("#embed-file-info");
    const embedFileName   = $("#embed-file-name");
    const embedFileClear  = $("#embed-file-clear");
    const embedMessage    = $("#embed-message");
    const embedPassword   = $("#embed-password");
    const embedAlgorithm  = $("#embed-algorithm");
    const embedBtn        = $("#embed-btn");
    const embedResult     = $("#embed-result");
    const embedStatus     = $("#embed-status");
    const charCount       = $("#embed-char-count");

    // Capacity
    const capacityCard    = $("#capacity-card");
    const capacityPct     = $("#capacity-pct");
    const capacityBarFill = $("#capacity-bar-fill");
    const capacityPayload = $("#capacity-payload");
    const capacityMax     = $("#capacity-max");
    const capacityDuration = $("#capacity-duration");
    const capacityChannels = $("#capacity-channels");
    const capacityRate     = $("#capacity-rate");

    // Extract
    const extractFile      = $("#extract-file");
    const extractDropZone  = $("#extract-drop-zone");
    const extractFilePrompt = $("#extract-file-prompt");
    const extractFileInfo  = $("#extract-file-info");
    const extractFileName  = $("#extract-file-name");
    const extractFileClear = $("#extract-file-clear");
    const extractPassword  = $("#extract-password");
    const extractBtn       = $("#extract-btn");
    const extractResult    = $("#extract-result");
    const extractStatus    = $("#extract-status");

    // Analyze
    const analyzeFile      = $("#analyze-file");
    const analyzeDropZone  = $("#analyze-drop-zone");
    const analyzeFilePrompt = $("#analyze-file-prompt");
    const analyzeFileInfo  = $("#analyze-file-info");
    const analyzeFileName  = $("#analyze-file-name");
    const analyzeFileClear = $("#analyze-file-clear");
    const analyzeBtn       = $("#analyze-btn");
    const analyzeResult    = $("#analyze-result");
    const analyzeStatus    = $("#analyze-status");

    // Loading
    const loadingOverlay   = $("#loading-overlay");
    const loadingLabel     = $("#loading-label");
    const loadingSub       = $("#loading-sub");

    /* ─── State ───────────────────────────────────────────────── */
    let embedCapacity = null;   // { max_message_chars, max_payload_bytes, total_samples }
    let embedAudioFile = null;
    let extractAudioFile = null;
    let analyzeAudioFile = null;

    /* ─── Helpers ─────────────────────────────────────────────── */

    function showLoading(label, sub) {
        loadingLabel.textContent = label || "PROCESSING…";
        loadingSub.textContent = sub || "Please wait";
        loadingOverlay.style.display = "flex";
    }

    async function fetchJsonSafely(url, options) {
        const res = await fetch(url, options);
        if (res.status === 413) {
            throw new Error("File too large (413). The server or host (e.g. Vercel) has a limit on upload size.");
        }
        if (res.status === 504) {
            throw new Error("Request timed out (504). Processing took too long for the serverless function.");
        }
        
        let data;
        try {
            data = await res.json();
        } catch (e) {
            if (!res.ok) {
                throw new Error(`Server error (${res.status}). Server returned non-JSON response.`);
            }
            throw new Error("Failed to parse JSON response from server.");
        }
        return { res, data };
    }

    function hideLoading() {
        loadingOverlay.style.display = "none";
    }

    function setStatus(el, text, type) {
        el.textContent = text;
        el.className = "panel-status" + (type ? " status--" + type : "");
    }

    function formatBytes(bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
        return (bytes / 1048576).toFixed(2) + " MB";
    }

    function estimatePayloadBits(msgLen) {
        // Approximate: Fernet ≈ (msg + 73) * 4/3 base64, then JSON overhead ~122 + 4 prefix
        if (msgLen <= 0) return 0;
        const fernetRaw = msgLen + 73;
        const fernetPadded = Math.ceil(fernetRaw / 16) * 16;
        const fernetToken = Math.ceil((1 + 8 + 16 + fernetPadded + 32) * 4 / 3);
        const jsonPayload = 122 + fernetToken;
        return (4 + jsonPayload) * 8;
    }

    /* ─── Capacity Visualiser ─────────────────────────────────── */

    function updateCapacityBar() {
        if (!embedCapacity) return;

        const msgLen = embedMessage.value.length;
        const maxChars = embedCapacity.max_message_chars;
        const pct = maxChars > 0 ? Math.min((msgLen / maxChars) * 100, 100) : 0;

        let pctText = pct.toFixed(1) + "%";
        if (msgLen > 0 && pct < 0.1) {
            pctText = "< 0.1%";
        }
        capacityPct.textContent = pctText;

        const visualPct = msgLen > 0 ? Math.max(pct, 1) : 0;
        capacityBarFill.style.width = visualPct + "%";

        const approxPayloadBits = estimatePayloadBits(msgLen);
        capacityPayload.textContent = "Payload: ~" + formatBytes(Math.ceil(approxPayloadBits / 8));
        capacityMax.textContent = "Max: ~" + maxChars.toLocaleString() + " chars";

        // Colour thresholds
        const warn = pct > 75;
        const error = pct > 95;
        capacityPct.className = "capacity-pct" + (error ? " error" : warn ? " warn" : "");
        capacityBarFill.className = "capacity-bar-fill" + (error ? " error" : warn ? " warn" : "");

        // Char counter
        charCount.textContent = msgLen.toLocaleString() + " characters";
        charCount.classList.toggle("over-capacity", msgLen > maxChars);
    }

    /* ─── Validation ──────────────────────────────────────────── */

    function validateEmbed() {
        const ok = embedAudioFile &&
                   embedMessage.value.trim().length > 0 &&
                   embedPassword.value.trim().length >= 4;
        embedBtn.disabled = !ok;
    }

    function validateExtract() {
        const ok = extractAudioFile &&
                   extractPassword.value.trim().length > 0;
        extractBtn.disabled = !ok;
    }

    function validateAnalyze() {
        const ok = analyzeAudioFile != null;
        analyzeBtn.disabled = !ok;
    }

    /* ─── File Upload Handlers ────────────────────────────────── */

    function setupFileDrop(dropZone, input, prompt, info, nameEl, clearBtn, onSelect, onClear) {
        // Drag events
        ["dragenter", "dragover"].forEach((evt) => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.add("dragover");
            });
        });
        ["dragleave", "drop"].forEach((evt) => {
            dropZone.addEventListener(evt, (e) => {
                e.preventDefault();
                dropZone.classList.remove("dragover");
            });
        });
        dropZone.addEventListener("drop", (e) => {
            const files = e.dataTransfer.files;
            if (files.length) {
                input.files = files;
                handleFile(files[0]);
            }
        });

        input.addEventListener("change", () => {
            if (input.files.length) handleFile(input.files[0]);
        });

        clearBtn.addEventListener("click", (e) => {
            e.stopPropagation();
            input.value = "";
            prompt.style.display = "";
            info.style.display = "none";
            onClear();
        });

        function handleFile(file) {
            if (!file.name.toLowerCase().endsWith(".wav")) {
                alert("Only .wav files are supported.");
                input.value = "";
                return;
            }
            nameEl.textContent = file.name + " (" + formatBytes(file.size) + ")";
            prompt.style.display = "none";
            info.style.display = "flex";
            onSelect(file);
        }
    }

    // Embed file
    setupFileDrop(
        embedDropZone, embedFile, embedFilePrompt,
        embedFileInfo, embedFileName, embedFileClear,
        async (file) => {
            embedAudioFile = file;
            validateEmbed();
            // Fetch capacity
            const fd = new FormData();
            fd.append("audio", file);
            try {
                const { res, data } = await fetchJsonSafely("/api/capacity", { method: "POST", body: fd });
                if (data.error) throw new Error(data.error);
                embedCapacity = data.capacity;
                capacityDuration.textContent = data.duration + "s";
                capacityChannels.textContent = data.channels + "ch";
                capacityRate.textContent = (data.sample_rate / 1000).toFixed(1) + " kHz";
                capacityCard.style.display = "";
                updateCapacityBar();
            } catch (err) {
                capacityCard.style.display = "none";
                embedCapacity = null;
            }
        },
        () => {
            embedAudioFile = null;
            embedCapacity = null;
            capacityCard.style.display = "none";
            validateEmbed();
        }
    );

    // Extract file
    setupFileDrop(
        extractDropZone, extractFile, extractFilePrompt,
        extractFileInfo, extractFileName, extractFileClear,
        (file) => { extractAudioFile = file; validateExtract(); },
        ()     => { extractAudioFile = null; validateExtract(); }
    );

    // Analyze file
    setupFileDrop(
        analyzeDropZone, analyzeFile, analyzeFilePrompt,
        analyzeFileInfo, analyzeFileName, analyzeFileClear,
        (file) => { analyzeAudioFile = file; validateAnalyze(); },
        ()     => { analyzeAudioFile = null; validateAnalyze(); }
    );

    /* ─── Input Listeners ─────────────────────────────────────── */

    embedMessage.addEventListener("input", () => {
        validateEmbed();
        updateCapacityBar();
    });
    embedPassword.addEventListener("input", validateEmbed);
    extractPassword.addEventListener("input", validateExtract);

    // Password toggles
    document.querySelectorAll(".pw-toggle").forEach((btn) => {
        btn.addEventListener("click", () => {
            const target = document.getElementById(btn.dataset.target);
            if (!target) return;
            const isPassword = target.type === "password";
            target.type = isPassword ? "text" : "password";
            btn.setAttribute("aria-label", isPassword ? "Hide password" : "Show password");
        });
    });

    /* ─── Embed ───────────────────────────────────────────────── */

    embedBtn.addEventListener("click", async () => {
        if (embedBtn.disabled) return;

        const fd = new FormData();
        fd.append("audio", embedAudioFile);
        fd.append("message", embedMessage.value);
        fd.append("password", embedPassword.value);
        if (embedAlgorithm) fd.append("algorithm", embedAlgorithm.value);

        showLoading("EMBEDDING…", "Encrypting and hiding your message");
        setStatus(embedStatus, "PROCESSING", "active");
        embedResult.style.display = "none";

        try {
            const { res, data } = await fetchJsonSafely("/api/embed", { method: "POST", body: fd });

            if (!res.ok || data.error) throw new Error(data.error || "Embedding failed");

            setStatus(embedStatus, "SUCCESS", "success");
            embedResult.className = "result-box result--success";
            embedResult.innerHTML = `
                <div class="result-title">✓ EMBEDDING COMPLETE</div>
                <div class="result-stats">
                    <span class="result-stat">Message: <span class="result-stat__value">${data.message_length} chars</span></span>
                    <span class="result-stat">Payload: <span class="result-stat__value">${formatBytes(data.payload_bytes)}</span></span>
                    <span class="result-stat">Capacity used: <span class="result-stat__value">${data.usage_percent}%</span></span>
                </div>
                <div style="display: flex; gap: 10px; flex-wrap: wrap;">
                    <a class="download-btn" href="/api/download/${encodeURIComponent(data.download_filename)}" download>
                        <svg viewBox="0 0 24 24" fill="none"><path d="M12 4v12m0 0l-4-4m4 4l4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                        DOWNLOAD STEGO FILE
                    </a>
                    <a class="download-btn" href="/api/report/${encodeURIComponent(data.download_filename)}" download style="background: var(--bg-elevated); color: var(--text-primary); border: 1px solid var(--border-subtle);">
                        <svg viewBox="0 0 24 24" fill="none"><path d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>
                        REPORT
                    </a>
                </div>
            `;
            embedResult.style.display = "";

        } catch (err) {
            setStatus(embedStatus, "ERROR", "error");
            embedResult.className = "result-box result--error";
            embedResult.innerHTML = `
                <div class="result-title">✗ EMBEDDING FAILED</div>
                <p>${escapeHtml(err.message)}</p>
            `;
            embedResult.style.display = "";
        } finally {
            hideLoading();
        }
    });

    /* ─── Extract ─────────────────────────────────────────────── */

    extractBtn.addEventListener("click", async () => {
        if (extractBtn.disabled) return;

        const fd = new FormData();
        fd.append("audio", extractAudioFile);
        fd.append("password", extractPassword.value);

        showLoading("EXTRACTING…", "Decrypting hidden message");
        setStatus(extractStatus, "PROCESSING", "active");
        extractResult.style.display = "none";

        try {
            const { res, data } = await fetchJsonSafely("/api/extract", { method: "POST", body: fd });

            if (!res.ok || data.error) throw new Error(data.error || "Extraction failed");

            setStatus(extractStatus, "SUCCESS", "success");
            extractResult.className = "result-box result--success";
            extractResult.innerHTML = `
                <div class="result-title">✓ EXTRACTION COMPLETE</div>
                <div class="result-message">${escapeHtml(data.message)}</div>
                <div class="result-stats">
                    <span class="result-stat">Length: <span class="result-stat__value">${data.message_length} chars</span></span>
                    <span class="result-stat">Integrity: <span class="result-stat__value">${data.integrity_verified ? "✓ Verified" : "✗ Failed"}</span></span>
                    ${data.algorithm ? `<span class="result-stat">Algorithm: <span class="result-stat__value">${escapeHtml(data.algorithm)}</span></span>` : ""}
                </div>
                ${data.report_filename ? `
                <a class="download-btn" href="/api/report/${encodeURIComponent(data.report_filename)}" download style="margin-top: 16px;">
                    <svg viewBox="0 0 24 24" fill="none"><path d="M12 4v12m0 0l-4-4m4 4l4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                    DOWNLOAD REPORT
                </a>` : ""}
            `;
            extractResult.style.display = "";

        } catch (err) {
            setStatus(extractStatus, "ERROR", "error");
            extractResult.className = "result-box result--error";
            extractResult.innerHTML = `
                <div class="result-title">✗ EXTRACTION FAILED</div>
                <p>${escapeHtml(err.message)}</p>
            `;
            extractResult.style.display = "";
        } finally {
            hideLoading();
        }
    });

    /* ─── Analyze ─────────────────────────────────────────────── */

    analyzeBtn.addEventListener("click", async () => {
        if (analyzeBtn.disabled) return;

        const fd = new FormData();
        fd.append("audio", analyzeAudioFile);

        showLoading("ANALYZING…", "Scanning for steganographic signatures");
        setStatus(analyzeStatus, "PROCESSING", "active");
        analyzeResult.style.display = "none";

        try {
            const { res, data } = await fetchJsonSafely("/api/analyze", { method: "POST", body: fd });

            if (!res.ok || data.error) throw new Error(data.error || "Analysis failed");

            // Define classes based on suspicion score
            let resultClass = "result-box";
            if (data.suspicion_score > 75) resultClass += " result--error";
            else if (data.suspicion_score > 35) resultClass += " result--warning";
            else resultClass += " result--success";

            setStatus(analyzeStatus, "SUCCESS", "success");
            analyzeResult.className = resultClass;
            
            let findingsHtml = "";
            if (data.findings && data.findings.length > 0) {
                findingsHtml = "<ul style='margin-top: 10px; margin-left: 20px; font-size: 0.82rem; line-height: 1.6;'>";
                data.findings.forEach(f => {
                    findingsHtml += `<li><strong style="color: var(--accent-${f.type === 'critical' ? 'red' : f.type === 'warning' ? 'amber' : 'cyan'});">[${f.type.toUpperCase()}]</strong> ${escapeHtml(f.message)}</li>`;
                });
                findingsHtml += "</ul>";
            } else {
                findingsHtml = "<p style='margin-top: 10px; font-size: 0.82rem;'>No suspicious signatures detected.</p>";
            }

            analyzeResult.innerHTML = `
                <div class="result-title">✓ ANALYSIS COMPLETE</div>
                <div class="result-stats">
                    <span class="result-stat">Verdict: <span class="result-stat__value">${escapeHtml(data.verdict)}</span></span>
                    <span class="result-stat">Suspicion Score: <span class="result-stat__value">${data.suspicion_score}/100</span></span>
                    <span class="result-stat">LSB Ratio: <span class="result-stat__value">${data.stats.lsb_ratio !== undefined ? data.stats.lsb_ratio.toFixed(4) : "N/A"}</span></span>
                </div>
                ${findingsHtml}
                ${data.report_filename ? `
                <a class="download-btn" href="/api/report/${encodeURIComponent(data.report_filename)}" download style="margin-top: 16px;">
                    <svg viewBox="0 0 24 24" fill="none"><path d="M12 4v12m0 0l-4-4m4 4l4-4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
                    DOWNLOAD FULL REPORT
                </a>` : ""}
            `;
            analyzeResult.style.display = "";

        } catch (err) {
            setStatus(analyzeStatus, "ERROR", "error");
            analyzeResult.className = "result-box result--error";
            analyzeResult.innerHTML = `
                <div class="result-title">✗ ANALYSIS FAILED</div>
                <p>${escapeHtml(err.message)}</p>
            `;
            analyzeResult.style.display = "";
        } finally {
            hideLoading();
        }
    });

    /* ─── Utils ───────────────────────────────────────────────── */

    function escapeHtml(str) {
        const div = document.createElement("div");
        div.textContent = str;
        return div.innerHTML;
    }

})();
