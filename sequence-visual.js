/**
 * Diagramme de séquence animé : Alice ↔ canal public ↔ Bob.
 * Public = observable sur le réseau ; secret = reste local.
 * Au survol : panneau avec le contenu réel (champs) ou une explication pour les secrets.
 */

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** @param {string} id */
function el(id) {
  const n = document.getElementById(id);
  if (!n) throw new Error(`#${id} manquant`);
  return n;
}

function fieldValue(id) {
  const n = document.getElementById(id);
  if (!n || !("value" in n)) return "";
  return String(
    /** @type {HTMLInputElement | HTMLTextAreaElement} */ (n).value,
  ).trim();
}

/**
 * @param {string} src
 * @returns {{ head: string; body: string }}
 */
function resolveHover(src) {
  switch (src) {
    case "alice-pub": {
      const v = fieldValue("alicePub");
      return {
        head: "Clé publique Alice (g^x mod p, base64)",
        body: v || "(vide — lance l’étape 1 pour générer)",
      };
    }
    case "bob-pub": {
      const v = fieldValue("bobPub");
      return {
        head: "Clé publique Bob (g^x mod p, base64)",
        body: v || "(vide — lance l’étape 1 pour générer)",
      };
    }
    case "ciphertext": {
      const v = fieldValue("cipherB64");
      return {
        head: "Ciphertext AES-CTR (base64)",
        body: v || "(vide — chiffre un message d’abord)",
      };
    }
    case "alice-plain":
      return {
        head: "Message en clair (Alice)",
        body: fieldValue("plainText") || "(vide)",
      };
    case "bob-plain": {
      const out = document.getElementById("decrypted");
      const t = out ? out.textContent.trim() : "";
      return {
        head: "Message déchiffré (Bob)",
        body: t || "(vide — déchiffre d’abord)",
      };
    }
    case "secret-priv":
      return {
        head: "Clé privée DH (MODP14)",
        body: "Exposant secret x (grand entier) : généré dans le navigateur et conservé uniquement en mémoire pour cette démo ; il n’est jamais affiché ni transmis.",
      };
    case "secret-aes":
      return {
        head: "Clé AES (HKDF)",
        body: "Clé symétrique dérivée localement (secret DH + HKDF). Les octets bruts ne sont pas exposés par cette page ; seul le chiffrement / déchiffrement est possible.",
      };
    default:
      return { head: "", body: "" };
  }
}

/**
 * @param {HTMLElement} node
 */
function wireHover(node) {
  const src = node.dataset.hoverSrc;
  if (!src || node.dataset.hoverWired === "1") return;
  node.dataset.hoverWired = "1";

  const panel = document.createElement("div");
  panel.className = "seq-hover-insert";
  panel.hidden = true;
  node.appendChild(panel);

  const refresh = () => {
    const { head, body } = resolveHover(src);
    panel.replaceChildren();
    const h = document.createElement("strong");
    h.className = "seq-hover-head";
    h.textContent = head;
    const pre = document.createElement("pre");
    pre.className = "seq-hover-pre";
    pre.textContent = body;
    panel.appendChild(h);
    panel.appendChild(pre);
  };

  node.addEventListener("mouseenter", () => {
    refresh();
    panel.hidden = false;
  });
  node.addEventListener("mouseleave", () => {
    panel.hidden = true;
  });
}

/** À appeler une fois au chargement (tags statiques du diagramme). */
export function initSequenceHoverUI() {
  el("seqStage")
    .querySelectorAll("[data-hover-src]")
    .forEach((n) => wireHover(/** @type {HTMLElement} */ (n)));
}

function setCaption(text) {
  el("seqCaption").textContent = text;
}

function clearChannelArtifacts() {
  el("channelArtifacts").replaceChildren();
}

export function resetSequenceVisual() {
  for (const id of [
    "tagAlicePriv",
    "tagAlicePub",
    "tagAliceAes",
    "tagAlicePlain",
    "tagBobPriv",
    "tagBobPub",
    "tagBobAes",
    "tagBobPlain",
  ]) {
    const t = el(id);
    t.dataset.active = "0";
    t.hidden = true;
  }
  clearChannelArtifacts();
  el("seqFlyLayer").replaceChildren();
  el("seqStage").classList.remove("seq-stage--pulse-secret");
  setCaption("");
}

/**
 * @param {"public"|"secret"} kind
 * @param {string} label
 * @param {"alice"|"bob"} start
 * @param {string} hoverSrc
 */
function spawnPacket(kind, label, start = "alice", hoverSrc = "") {
  const layer = el("seqFlyLayer");
  const p = document.createElement("div");
  p.className = `seq-packet seq-packet--${kind}`;
  p.dataset.pos = start;
  if (hoverSrc) p.dataset.hoverSrc = hoverSrc;
  const span = document.createElement("span");
  span.className = "seq-packet-label";
  span.textContent = label;
  p.appendChild(span);
  const badge = document.createElement("span");
  badge.className = "seq-packet-badge";
  badge.textContent = kind === "public" ? "Public" : "Secret";
  p.appendChild(badge);
  layer.appendChild(p);
  wireHover(p);
  return p;
}

/**
 * @param {HTMLElement} packet
 * @param {"alice"|"channel"|"bob"} pos
 */
function movePacket(packet, pos) {
  packet.dataset.pos = pos;
  return sleep(1050);
}

/**
 * @param {HTMLElement} packet
 * @param {string} note
 */
function pinInChannel(packet, note) {
  packet.classList.add("seq-packet--ghost");
  const shelf = el("channelArtifacts");
  const label = packet.querySelector(".seq-packet-label")?.textContent ?? "?";
  const pin = document.createElement("div");
  pin.className = "seq-channel-pin seq-channel-pin--public";
  pin.innerHTML = `<span class="seq-channel-pin-label">${label}</span><span class="seq-channel-pin-note">${note}</span>`;
  if (packet.dataset.hoverSrc) pin.dataset.hoverSrc = packet.dataset.hoverSrc;
  shelf.appendChild(pin);
  wireHover(pin);
}

function revealTag(id) {
  const t = el(id);
  t.hidden = false;
  t.dataset.active = "1";
}

/** Après génération des clés (DH + AES). */
export async function animateKeyExchange() {
  resetSequenceVisual();
  setCaption(
    "Alice génère une paire DH (MODP14) : exposant privé (secret) et clé publique g^x mod p.",
  );

  revealTag("tagAlicePriv");
  revealTag("tagAlicePub");
  await sleep(1000);

  setCaption(
    "Alice envoie sa clé publique sur le canal — tout le monde peut la lire.",
  );
  const pA = spawnPacket("public", "k_pub_A", "alice", "alice-pub");
  await movePacket(pA, "channel");
  pinInChannel(pA, "observable");
  await sleep(550);
  await movePacket(pA, "bob");
  pA.remove();
  await sleep(650);

  setCaption("Bob génère sa paire : clé privée secrète et clé publique.");
  revealTag("tagBobPriv");
  revealTag("tagBobPub");
  await sleep(1000);

  setCaption("Bob renvoie sa clé publique sur le canal (également public).");
  const pB = spawnPacket("public", "k_pub_B", "bob", "bob-pub");
  await movePacket(pB, "channel");
  pinInChannel(pB, "observable");
  await sleep(550);
  await movePacket(pB, "alice");
  pB.remove();
  await sleep(500);

  setCaption(
    "Les clés privées ne quittent jamais Alice ni Bob. Secret DH + HKDF → clé AES, calculés localement.",
  );
  revealTag("tagAliceAes");
  revealTag("tagBobAes");
  el("seqStage").classList.add("seq-stage--pulse-secret");
  await sleep(1500);
  el("seqStage").classList.remove("seq-stage--pulse-secret");

  setCaption(
    "Sur le canal : uniquement des éléments publics. Les secrets restent sur les machines.",
  );
}

/** Après chiffrement. */
export async function animateEncrypt() {
  setCaption("Le message en clair reste secret chez Alice avant chiffrement.");
  revealTag("tagAlicePlain");
  await sleep(750);

  setCaption(
    "Alice envoie le ciphertext AES-CTR sur le canal : public, mais inexploitable sans la clé AES.",
  );
  const c = spawnPacket("public", "Ciphertext AES-CTR", "alice", "ciphertext");
  await movePacket(c, "channel");
  pinInChannel(c, "interceptable sans K_AES");
  await sleep(500);
  await movePacket(c, "bob");
  c.remove();
  await sleep(400);
  setCaption(
    "Bob reçoit le ciphertext ; déchiffrement avec sa clé AES (jamais transmise).",
  );
}

/** Après déchiffrement réussi. */
export async function animateDecrypt() {
  revealTag("tagBobPlain");
  el("seqStage").classList.add("seq-stage--pulse-secret");
  await sleep(900);
  el("seqStage").classList.remove("seq-stage--pulse-secret");
  setCaption(
    "Le texte en clair réapparaît uniquement chez Bob — il ne repasse pas sur le canal.",
  );
}

export async function replayKeyExchangeAnimation(keysReady) {
  if (!keysReady) {
    setCaption("Utilise d’abord le bouton 1 pour générer les clés.");
    await sleep(2000);
    setCaption("");
    return;
  }
  await animateKeyExchange();
}
