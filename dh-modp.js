/**
 * Diffie-Hellman sur groupe multiplicatif (Z/pZ)* : RFC 3526 MODP Group 14 (2048 bits), g = 2.
 * Exponentiation modulaire explicite (square-and-multiply) avec BigInt.
 */

/** RFC 3526 — 2048-bit MODP Group (prime only). */
const MODP14_HEX =
  "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A889FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED52907709696D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFFF";

let _cachedP = null;
let _cachedByteLength = 0;

/**
 * @returns {{ p: bigint; g: bigint; byteLength: number }}
 */
export function getDHParameters() {
  if (_cachedP === null) {
    _cachedP = BigInt(`0x${MODP14_HEX}`);
    _cachedByteLength = Math.ceil(MODP14_HEX.length / 2);
  }
  return { p: _cachedP, g: 2n, byteLength: _cachedByteLength };
}

/**
 * (base^exp) mod mod — exponentiation modulaire binaire.
 * @param {bigint} base
 * @param {bigint} exp
 * @param {bigint} mod
 */
export function modPow(base, exp, mod) {
  let b = base % mod;
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % mod;
    b = (b * b) % mod;
    e >>= 1n;
  }
  return r;
}

/**
 * Exposant privé aléatoire dans [2, p − 2] (rejet minimal, 32 octets d’entropie).
 * @param {bigint} p
 */
export function randomPrivateExponent(p) {
  const hi = p - 3n;
  if (hi <= 0n) throw new Error("p trop petit");
  const buf = new Uint8Array(32);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    let x = 0n;
    for (let i = 0; i < buf.length; i++) x = (x << 8n) | BigInt(buf[i]);
    x = (x % hi) + 2n;
    if (x >= 2n && x <= p - 2n) return x;
  }
}

/**
 * @param {bigint} p
 * @param {bigint} g
 * @returns {{ privateKey: bigint; publicKey: bigint }}
 */
export function generateDHKeyPair(p, g) {
  const privateKey = randomPrivateExponent(p);
  const publicKey = modPow(g, privateKey, p);
  return { privateKey, publicKey };
}

/**
 * Secret partagé ZZ = peerPublic^private mod p.
 * @param {bigint} privateKey
 * @param {bigint} peerPublicKey
 * @param {bigint} p
 */
export function computeSharedSecret(privateKey, peerPublicKey, p) {
  if (peerPublicKey <= 1n || peerPublicKey >= p) {
    throw new Error("Clé publique DH invalide.");
  }
  return modPow(peerPublicKey, privateKey, p);
}

/**
 * Encode un entier positif sur exactement `len` octets (big-endian, zéros à gauche).
 * @param {bigint} n
 * @param {number} len
 */
export function bigintToFixedBytes(n, len) {
  if (n < 0n) throw new Error("n doit être positif");
  const out = new Uint8Array(len);
  let x = n;
  for (let i = len - 1; i >= 0 && x > 0n; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  if (x > 0n) throw new Error("Entier trop grand pour la taille fixe.");
  return out;
}

/**
 * @param {Uint8Array} buf
 */
export function fixedBytesToBigInt(buf) {
  let v = 0n;
  for (let i = 0; i < buf.length; i++) v = (v << 8n) | BigInt(buf[i]);
  return v;
}
