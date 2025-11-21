const DEMO_EMAIL = "cm@epidi.com";
const DEMO_PASSWORD = "Test1234!";

// --- Static AES-CBC config (must match Kotlin) ---
const CONFIG_KEY_B64 = "xGIPtGtgoLwoB4mePc/bAAbi1kDAXF3vw2CxC7uxrC4=";
const CONFIG_IV_B64  = "4yYUnxeWssX13VJJRh7IZA==";

// ---- Base64 helpers ----
function bytesToBase64(bytes) {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Decode static key & IV from Base64
const KEY_BYTES = base64ToBytes(CONFIG_KEY_B64);
const IV_BYTES = base64ToBytes(CONFIG_IV_B64); // 16 bytes

let cachedKeyPromise = null;

// ---- Import static AES-CBC key ----
function getAesCbcKey() {
  if (!cachedKeyPromise) {
    cachedKeyPromise = crypto.subtle.importKey(
      "raw",
      KEY_BYTES,
      { name: "AES-CBC" },
      false,
      ["encrypt", "decrypt"]
    );
  }
  return cachedKeyPromise;
}

// ---- Encrypt (AES/CBC/PKCS5/PKCS7) ----
async function encryptAesCbcPkcs7(plaintext) {
  const key = await getAesCbcKey();
  const enc = new TextEncoder();
  const data = enc.encode(plaintext);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: IV_BYTES, // static IV (like your Kotlin code)
    },
    key,
    data
  );

  const encryptedBytes = new Uint8Array(encryptedBuffer);
  return bytesToBase64(encryptedBytes);
}

// ---- Decrypt (AES/CBC/PKCS5/PKCS7) ----
async function decryptAesCbcPkcs7(base64Ciphertext) {
  const key = await getAesCbcKey();
  const cipherBytes = base64ToBytes(base64Ciphertext.trim());

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: IV_BYTES,
    },
    key,
    cipherBytes
  );

  const dec = new TextDecoder();
  return dec.decode(decryptedBuffer);
}

// ---- UI wiring ----
document.addEventListener("DOMContentLoaded", () => {
  const loginSection = document.getElementById("login-section");
  const appSection = document.getElementById("app-section");

  const loginForm = document.getElementById("login-form");
  const loginEmail = document.getElementById("login-email");
  const loginPassword = document.getElementById("login-password");
  const loginError = document.getElementById("login-error");

  // we still grab this element, but it's no longer used for crypto (key is static)
  const cryptoPasswordInput = document.getElementById("crypto-password");

  const plaintextInput = document.getElementById("plaintext");
  const ciphertextOut = document.getElementById("ciphertext-out");
  const ciphertextIn = document.getElementById("ciphertext-in");
  const plaintextOut = document.getElementById("plaintext-out");
  const encryptBtn = document.getElementById("encrypt-btn");
  const decryptBtn = document.getElementById("decrypt-btn");
  const statusEl = document.getElementById("status");

  function showStatus(msg, isError = false) {
    statusEl.textContent = msg;
    statusEl.style.color = isError ? "#fecaca" : "#a5b4fc";
  }

  // Login logic (hard-coded)
  loginForm.addEventListener("submit", (e) => {
    e.preventDefault();
    loginError.textContent = "";

    const email = loginEmail.value.trim();
    const password = loginPassword.value;

    if (email === DEMO_EMAIL && password === DEMO_PASSWORD) {
      loginSection.classList.add("hidden");
      appSection.classList.remove("hidden");
      showStatus("Logged in. Ready to encrypt/decrypt.");
    } else {
      loginError.textContent = "Invalid email or password.";
    }
  });

  // Encrypt button
  encryptBtn.addEventListener("click", async () => {
    const plaintext = plaintextInput.value;

    if (!plaintext) {
      showStatus("Enter some plaintext to encrypt.", true);
      return;
    }

    try {
      showStatus("Encrypting...");
      const ctBase64 = await encryptAesCbcPkcs7(plaintext);
      ciphertextOut.value = ctBase64;
      ciphertextIn.value = ctBase64;
      showStatus("Encryption successful.");
    } catch (err) {
      console.error(err);
      showStatus("Encryption failed: " + err.message, true);
    }
  });

  // Decrypt button
  decryptBtn.addEventListener("click", async () => {
    const cipherB64 = ciphertextIn.value.trim();

    if (!cipherB64) {
      showStatus("Paste Base64 ciphertext to decrypt.", true);
      return;
    }

    try {
      showStatus("Decrypting...");
      const pt = await decryptAesCbcPkcs7(cipherB64);
      plaintextOut.value = pt;
      showStatus("Decryption successful.");
    } catch (err) {
      console.error(err);
      showStatus("Decryption failed: " + err.message, true);
    }
  });
});
