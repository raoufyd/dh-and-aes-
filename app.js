/**
 * Diffie-Hellman classique (MODP14, g=2) + HKDF (Web Crypto) + AES-CTR (implémentation maison).
 */

import { aesCtrDecrypt, aesCtrEncrypt } from "./aes.js";
import {
  bigintToFixedBytes,
  computeSharedSecret,
  generateDHKeyPair,
  getDHParameters,
} from "./dh-modp.js";
import {
  animateDecrypt,
  animateEncrypt,
  animateKeyExchange,
  initSequenceHoverUI,
  replayKeyExchangeAnimation,
} from "./sequence-visual.js";

const HKDF_INFO = new TextEncoder().encode("tp-sec-dh-aes-v1");

/** @type {{ privateKey: bigint; publicKey: bigint } | null} */
let aliceKeys = null;
/** @type {{ privateKey: bigint; publicKey: bigint } | null} */
let bobKeys = null;
/** @type {Uint8Array | null} */
let aliceAes = null;
/** @type {Uint8Array | null} */
let bobAes = null;

const $ = (id) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`#${id} introuvable`);
  return el;
};

function b64encode(buf) {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : buf;
  let bin = "";
  bytes.forEach((b) => {
    bin += String.fromCharCode(b);
  });
  return btoa(bin);
}

function b64decode(str) {
  const bin = atob(str.replace(/\s/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function getAesBits() {
  return Number($("aesSize").value);
}

function assertSubtle() {
  if (!globalThis.crypto?.subtle) {
    throw new Error(
      "Web Crypto indisponible. Ouvre la page via http://localhost (ex. npx serve) ou HTTPS.",
    );
  }
}

/**
 * Secret DH → HKDF-SHA256 → octets de clé AES (128/192/256 bits).
 * @param {Uint8Array} sharedSecretBytes
 * @param {number} aesBits
 */
async function deriveAesKeyBytesFromDhSecret(sharedSecretBytes, aesBits) {
  const hkdfMaterial = await crypto.subtle.importKey(
    "raw",
    sharedSecretBytes,
    "HKDF",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: HKDF_INFO,
    },
    hkdfMaterial,
    aesBits,
  );
  return new Uint8Array(bits);
}

function showError(msg) {
  const el = $("cryptoError");
  el.textContent = msg;
  el.hidden = false;
}

function clearError() {
  const el = $("cryptoError");
  el.textContent = "";
  el.hidden = true;
}

async function setup() {
  assertSubtle();
  clearError();
  $("setupStatus").textContent = "Calcul DH (MODP 2048)…";
  $("btnEncrypt").disabled = true;
  $("btnDecrypt").disabled = true;
  $("cipherB64").value = "";
  $("decrypted").textContent = "";

  const bits = getAesBits();
  const { p, g, byteLength } = getDHParameters();

  aliceKeys = generateDHKeyPair(p, g);
  bobKeys = generateDHKeyPair(p, g);

  const zzAlice = computeSharedSecret(
    aliceKeys.privateKey,
    bobKeys.publicKey,
    p,
  );
  const zzBob = computeSharedSecret(bobKeys.privateKey, aliceKeys.publicKey, p);
  if (zzAlice !== zzBob) {
    throw new Error("Secret DH incohérent.");
  }

  const zzBytes = bigintToFixedBytes(zzAlice, byteLength);
  const keyBytes = await deriveAesKeyBytesFromDhSecret(zzBytes, bits);
  aliceAes = keyBytes;
  bobAes = keyBytes;

  $("alicePub").value = b64encode(
    bigintToFixedBytes(aliceKeys.publicKey, byteLength),
  );
  $("bobPub").value = b64encode(
    bigintToFixedBytes(bobKeys.publicKey, byteLength),
  );

  $("btnEncrypt").disabled = false;
  $("btnDecrypt").disabled = false;
  $(
    "setupStatus",
  ).textContent = `Prêt — DH MODP14 + AES-${bits} CTR (HKDF + AES maison).`;

  await animateKeyExchange();
}

async function encryptMessage() {
  clearError();
  if (!aliceAes) {
    showError("Génère d’abord les clés.");
    return;
  }
  const text = $("plainText").value;
  if (!text) {
    showError("Saisis un message.");
    return;
  }
  const combined = aesCtrEncrypt(aliceAes, new TextEncoder().encode(text));
  $("cipherB64").value = b64encode(combined);
  await animateEncrypt();
}

async function decryptMessage() {
  clearError();
  if (!bobAes) {
    showError("Génère d’abord les clés.");
    return;
  }
  const b64 = $("cipherB64").value.trim();
  if (!b64) {
    showError("Aucun message chiffré.");
    return;
  }
  try {
    const combined = b64decode(b64);
    const out = new TextDecoder().decode(aesCtrDecrypt(bobAes, combined));
    $("decrypted").textContent = out;
    await animateDecrypt();
  } catch (e) {
    showError(e instanceof Error ? e.message : String(e));
    $("decrypted").textContent = "";
  }
}

$("btnSetup").addEventListener("click", () => {
  setup().catch((e) => {
    showError(e instanceof Error ? e.message : String(e));
    $("setupStatus").textContent = "";
  });
});
$("btnEncrypt").addEventListener("click", () => {
  encryptMessage().catch((e) =>
    showError(e instanceof Error ? e.message : String(e)),
  );
});
$("btnDecrypt").addEventListener("click", () => {
  decryptMessage().catch((e) =>
    showError(e instanceof Error ? e.message : String(e)),
  );
});

$("btnReplaySeq").addEventListener("click", () => {
  replayKeyExchangeAnimation(aliceKeys != null && bobKeys != null).catch((e) =>
    showError(e instanceof Error ? e.message : String(e)),
  );
});

initSequenceHoverUI();
