// ==========================================================================
// Encrypted TCP Chat - RSA & AES Cryptographic Dashboard Logic
// ==========================================================================

const API_BASE = "";

// State
let currentStatus = null;
let currentSelectedFile = null;
let historyItems = [];

// DOM Elements
const msgInput = document.getElementById("msgInput");
const btnSendMessage = document.getElementById("btnSendMessage");
const btnSendFile = document.getElementById("btnSendFile");
const fileDropzone = document.getElementById("fileDropzone");
const fileInput = document.getElementById("fileInput");
const selectedFileName = document.getElementById("selectedFileName");
const btnRegenKeys = document.getElementById("btnRegenKeys");
const btnViewKeys = document.getElementById("btnViewKeys");
const btnClearChat = document.getElementById("btnClearChat");
const rsaBitsSelect = document.getElementById("rsaBitsSelect");

const headerAlgorithmBadge = document.getElementById("headerAlgorithmBadge");
const flowStep1Text = document.getElementById("flowStep1Text");
const bobConnectionStatus = document.getElementById("bobConnectionStatus");
const bobCipherTag = document.getElementById("bobCipherTag");
const aliceConnectionStatus = document.getElementById("aliceConnectionStatus");
const aliceCipherTag = document.getElementById("aliceCipherTag");
const aliceKeyCardTitle = document.getElementById("aliceKeyCardTitle");
const wireRsaWrapLabel = document.getElementById("wireRsaWrapLabel");

const wireStatusBadge = document.getElementById("wireStatusBadge");
const wireEmptyState = document.getElementById("wireEmptyState");
const wireDetails = document.getElementById("wireDetails");
const wireAesKey = document.getElementById("wireAesKey");
const wireNonce = document.getElementById("wireNonce");
const wireTag = document.getElementById("wireTag");
const wireCiphertext = document.getElementById("wireCiphertext");
const wireEncryptedAesKey = document.getElementById("wireEncryptedAesKey");
const wirePacketRaw = document.getElementById("wirePacketRaw");
const wirePacketSize = document.getElementById("wirePacketSize");
const wireLatency = document.getElementById("wireLatency");

const aliceKeyPreview = document.getElementById("aliceKeyPreview");
const receivedFeed = document.getElementById("receivedFeed");
const feedCount = document.getElementById("feedCount");

// Modal Elements
const keysModal = document.getElementById("keysModal");
const btnCloseModal = document.getElementById("btnCloseModal");
const btnModalCloseAction = document.getElementById("btnModalCloseAction");
const modalPublicKey = document.getElementById("modalPublicKey");
const modalPrivateKey = document.getElementById("modalPrivateKey");
const modalTitle = document.getElementById("modalTitle");
const modalFooterNote = document.getElementById("modalFooterNote");

// Initial Setup
document.addEventListener("DOMContentLoaded", () => {
  fetchStatus();
  fetchHistory();
  setupEventListeners();
});

function setupEventListeners() {
  // Send Message
  btnSendMessage.addEventListener("click", handleSendMessage);

  // Quick prompt buttons
  document.querySelectorAll(".chip-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      msgInput.value = btn.getAttribute("data-text");
      msgInput.focus();
    });
  });

  // File Upload Handlers
  fileDropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", handleFileSelected);

  fileDropzone.addEventListener("dragover", (e) => {
    e.preventDefault();
    fileDropzone.classList.add("drag-over");
  });
  fileDropzone.addEventListener("dragleave", () => {
    fileDropzone.classList.remove("drag-over");
  });
  fileDropzone.addEventListener("drop", (e) => {
    e.preventDefault();
    fileDropzone.classList.remove("drag-over");
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      fileInput.files = e.dataTransfer.files;
      handleFileSelected();
    }
  });

  btnSendFile.addEventListener("click", handleSendFile);

  // Key actions & bits selection
  btnRegenKeys.addEventListener("click", handleRegenerateKeys);
  if (rsaBitsSelect) {
    rsaBitsSelect.addEventListener("change", () => {
      handleRegenerateKeys(parseInt(rsaBitsSelect.value, 10));
    });
  }
  btnViewKeys.addEventListener("click", openKeysModal);
  btnCloseModal.addEventListener("click", closeKeysModal);
  btnModalCloseAction.addEventListener("click", closeKeysModal);

  // Clear chat
  btnClearChat.addEventListener("click", handleClearChat);
}

// -----------------------------------------------------------------------------
// API Calls & Dynamic Updates
// -----------------------------------------------------------------------------

async function fetchStatus() {
  try {
    const res = await fetch(`${API_BASE}/api/status`);
    if (!res.ok) throw new Error("Failed to load status");
    currentStatus = await res.json();
    applyDynamicStatus(currentStatus);
  } catch (err) {
    console.error("Error fetching status:", err);
    aliceKeyPreview.textContent = "Error connecting to Alice's RSA Server.";
    aliceConnectionStatus.textContent = "• Server Offline";
    aliceConnectionStatus.className = "connection-status status-offline";
  }
}

function applyDynamicStatus(status) {
  if (!status) return;

  const alice = status.alice;
  const bob = status.bob;

  if (alice) {
    const bits = alice.rsa_bits || 1024;
    headerAlgorithmBadge.textContent = `RSA-${bits} + AES-GCM`;
    flowStep1Text.textContent = `Alice exports RSA-${bits} Public Key`;
    aliceKeyCardTitle.textContent = `Alice's Public Key (RSA-${bits})`;
    aliceCipherTag.textContent = `RSA-${bits}`;
    aliceConnectionStatus.textContent = `• TCP Listening on ${alice.host}:${alice.port}`;
    aliceConnectionStatus.className = "connection-status status-listening";
    aliceKeyPreview.textContent = alice.public_key_pem;
    modalPublicKey.value = alice.public_key_pem;
    modalPrivateKey.value = alice.private_key_pem;
    modalTitle.textContent = `Alice's RSA-${bits} Keypair Details`;
    modalFooterNote.textContent = `RSA-${bits} with PKCS#1 OAEP padding scheme`;
    wireRsaWrapLabel.textContent = `AES Key Encrypted via Alice's Public RSA-${bits} Key (PKCS#1 OAEP)`;

    if (rsaBitsSelect && rsaBitsSelect.value !== String(bits)) {
      rsaBitsSelect.value = String(bits);
    }
  }

  if (bob) {
    bobConnectionStatus.textContent = `• Connected to ${bob.connected_to}`;
    bobConnectionStatus.className = "connection-status status-online";
    bobCipherTag.textContent = bob.cipher || "AES-256-GCM";
  }
}

async function fetchHistory() {
  try {
    const res = await fetch(`${API_BASE}/api/history`);
    if (!res.ok) throw new Error("Failed to load history");
    historyItems = await res.json();
    renderFeed();
  } catch (err) {
    console.error("Error fetching history:", err);
  }
}

async function handleSendMessage() {
  const text = msgInput.value.trim();
  if (!text) return;

  const tamperMode = document.querySelector('input[name="tamperMode"]:checked').value;
  const tamperCiphertext = tamperMode === "ciphertext";
  const tamperTag = tamperMode === "tag";

  setSendingState(true);

  try {
    const res = await fetch(`${API_BASE}/api/send-message`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: text,
        tamper_ciphertext: tamperCiphertext,
        tamper_tag: tamperTag,
      }),
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to send message");
    }

    const item = await res.json();
    historyItems.push(item);

    displayWireBreakdown(item);
    renderFeed();

    // Reset input
    msgInput.value = "";
  } catch (err) {
    alert("Error sending message: " + err.message);
  } finally {
    setSendingState(false);
  }
}

function handleFileSelected() {
  if (fileInput.files && fileInput.files[0]) {
    currentSelectedFile = fileInput.files[0];
    selectedFileName.textContent = `${currentSelectedFile.name} (${formatBytes(currentSelectedFile.size)})`;
    btnSendFile.style.display = "inline-flex";
  }
}

async function handleSendFile() {
  if (!currentSelectedFile) return;

  const tamperMode = document.querySelector('input[name="tamperMode"]:checked').value;
  const tamperCiphertext = tamperMode === "ciphertext";
  const tamperTag = tamperMode === "tag";

  const formData = new FormData();
  formData.append("file", currentSelectedFile);
  formData.append("tamper_ciphertext", tamperCiphertext);
  formData.append("tamper_tag", tamperTag);

  btnSendFile.disabled = true;
  btnSendFile.innerHTML = `<span>Encrypting & Sending File...</span>`;

  try {
    const res = await fetch(`${API_BASE}/api/send-file`, {
      method: "POST",
      body: formData,
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.detail || "Failed to send file");
    }

    const item = await res.json();
    historyItems.push(item);
    displayWireBreakdown(item);
    renderFeed();

    // Reset file input
    currentSelectedFile = null;
    fileInput.value = "";
    selectedFileName.textContent = "Choose or drag & drop a file";
    btnSendFile.style.display = "none";
  } catch (err) {
    alert("Error sending file: " + err.message);
  } finally {
    btnSendFile.disabled = false;
    btnSendFile.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
      <span>Encrypt & Send File</span>
    `;
  }
}

async function handleRegenerateKeys(targetBits) {
  const bits = targetBits || (rsaBitsSelect ? parseInt(rsaBitsSelect.value, 10) : 1024);
  try {
    btnRegenKeys.disabled = true;
    btnRegenKeys.textContent = "Regenerating...";
    const res = await fetch(`${API_BASE}/api/regenerate-keys`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ bits: bits })
    });
    if (!res.ok) throw new Error("Failed to regenerate keys");
    await fetchStatus();
  } catch (err) {
    alert("Error regenerating keys: " + err.message);
  } finally {
    btnRegenKeys.disabled = false;
    btnRegenKeys.innerHTML = `
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"></path></svg>
      Regenerate
    `;
  }
}

async function handleClearChat() {
  try {
    await fetch(`${API_BASE}/api/clear`, { method: "POST" });
    historyItems = [];
    renderFeed();
    wireEmptyState.style.display = "flex";
    wireDetails.style.display = "none";
    wireStatusBadge.textContent = "Idle";
    wireStatusBadge.style.color = "#38bdf8";
  } catch (err) {
    console.error("Error clearing chat:", err);
  }
}

// -----------------------------------------------------------------------------
// UI Renderers
// -----------------------------------------------------------------------------

function setSendingState(isSending) {
  btnSendMessage.disabled = isSending;
  if (isSending) {
    btnSendMessage.innerHTML = `<span>Encrypting & Transmitting...</span>`;
    wireStatusBadge.textContent = "Encrypting...";
    wireStatusBadge.style.color = "#f59e0b";
  } else {
    btnSendMessage.innerHTML = `
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="22" y1="2" x2="11" y2="13"></line><polygon points="22 2 15 22 11 13 2 9 22 2"></polygon></svg>
      <span>Encrypt & Send Message</span>
    `;
  }
}

function displayWireBreakdown(item) {
  const cb = item.crypto_breakdown;
  if (!cb) return;

  wireEmptyState.style.display = "none";
  wireDetails.style.display = "block";

  wireAesKey.textContent = cb.aes_key_hex || "--";
  wireNonce.textContent = cb.nonce_hex || "--";
  wireTag.textContent = cb.tag_hex || "--";
  wireCiphertext.textContent = cb.ciphertext_hex || (cb.ciphertext_len ? `[Binary File Ciphertext: ${cb.ciphertext_len} bytes]` : "--");
  wireEncryptedAesKey.textContent = cb.encrypted_aes_key_hex || "--";

  if (item.is_tampered || !item.gcm_verified) {
    wireStatusBadge.textContent = "Tampered Packet Transmitted";
    wireStatusBadge.style.color = "#ef4444";
  } else {
    wireStatusBadge.textContent = "Packet Verified & Decrypted";
    wireStatusBadge.style.color = "#10b981";
  }

  wirePacketSize.textContent = `Total Wire Size: ${cb.wire_total_bytes} bytes`;
  wireLatency.textContent = `Latency: ${item.duration_ms} ms`;
  wirePacketRaw.textContent = cb.wire_packet_preview_b64 || `Packet size: ${cb.wire_total_bytes} bytes`;
}

function renderFeed() {
  feedCount.textContent = `${historyItems.length} item${historyItems.length === 1 ? "" : "s"}`;

  if (historyItems.length === 0) {
    receivedFeed.innerHTML = `
      <div class="feed-empty-state">
        <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="1.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"></path></svg>
        <span>Waiting for Bob to send encrypted messages...</span>
      </div>
    `;
    return;
  }

  receivedFeed.innerHTML = "";
  historyItems.slice().reverse().forEach((item) => {
    const el = document.createElement("div");
    const isSuccess = item.gcm_verified && !item.is_tampered;
    el.className = `feed-item ${isSuccess ? "feed-item-success" : "feed-item-tampered"}`;

    const rsaBitsUsed = (item.crypto_breakdown && item.crypto_breakdown.rsa_bits) || 1024;

    let bodyHtml = "";
    if (item.type === "text") {
      if (isSuccess) {
        bodyHtml = `<div class="feed-item-content">${escapeHtml(item.decrypted_text || item.plaintext)}</div>`;
      } else {
        bodyHtml = `
          <div class="feed-tamper-warning">
            <strong>⚠️ Cryptographic Integrity Violation:</strong>
            <p>${escapeHtml(item.gcm_error || item.tamper_note || "Ciphertext or Tag corrupted!")}</p>
            <p style="margin-top: 4px; font-size: 0.7rem; color: #fecaca;">
              <em>Alice rejected this transmission because the AES-GCM MAC Tag did not match the wire data.</em>
            </p>
          </div>
        `;
      }
    } else if (item.type === "file") {
      if (isSuccess && item.download_url) {
        bodyHtml = `
          <div class="feed-file-box">
            <div class="file-info-group">
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#38bdf8" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path><polyline points="14 2 14 8 20 8"></polyline><line x1="16" y1="13" x2="8" y2="13"></line><line x1="16" y1="17" x2="8" y2="17"></line><polyline points="10 9 9 9 8 9"></polyline></svg>
              <div>
                <div class="file-name-text">${escapeHtml(item.filename)}</div>
                <div class="file-size-text">${formatBytes(item.file_size)} &bull; Decrypted & Saved</div>
              </div>
            </div>
            <a href="${item.download_url}" class="btn btn-secondary btn-sm" download="${escapeHtml(item.filename)}">
              Download
            </a>
          </div>
        `;
      } else {
        bodyHtml = `
          <div class="feed-tamper-warning">
            <strong>⚠️ Corrupted File Rejected:</strong>
            <p>${escapeHtml(item.gcm_error || item.tamper_note || "File ciphertext or tag tampered!")}</p>
          </div>
        `;
      }
    }

    el.innerHTML = `
      <div class="feed-item-header">
        <span class="feed-item-sender">Bob &rarr; Alice</span>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="feed-item-time">${item.timestamp}</span>
          <span class="feed-status-badge ${isSuccess ? "badge-verified" : "badge-tampered"}">
            ${isSuccess ? "&check; AES-GCM Validated" : "&times; Tamper Detected"}
          </span>
        </div>
      </div>
      ${bodyHtml}
      <div class="feed-item-footer">
        <span>AES-256 + RSA-${rsaBitsUsed}</span>
        <button class="inspect-btn" data-id="${item.id}">Inspect Wire Packet &rarr;</button>
      </div>
    `;

    el.querySelector(".inspect-btn").addEventListener("click", () => {
      displayWireBreakdown(item);
    });

    receivedFeed.appendChild(el);
  });
}

// -----------------------------------------------------------------------------
// Helpers & Modal
// -----------------------------------------------------------------------------

function openKeysModal() {
  keysModal.style.display = "flex";
}

function closeKeysModal() {
  keysModal.style.display = "none";
}

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return "0 Bytes";
  const k = 1024;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function escapeHtml(str) {
  if (!str) return "";
  return str.replace(/[&<>"']/g, (m) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#039;",
  }[m]));
}
