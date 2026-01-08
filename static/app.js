function randId() {
  return Math.random().toString(16).slice(2, 10);
}

function nowTime() {
  const d = new Date();
  return d.toLocaleTimeString([], {hour: "2-digit", minute: "2-digit"});
}

function b64encode(buf) {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

function b64decode(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

// UI
const statusEl = document.getElementById("status");
const roomEl = document.getElementById("room");
const myIdEl = document.getElementById("myId");
const peerIdEl = document.getElementById("peerId");
const connectBtn = document.getElementById("connectBtn");
const handshakeBtn = document.getElementById("handshakeBtn");
const rosterEl = document.getElementById("roster");
const cryptoStateEl = document.getElementById("cryptoState");
const messagesEl = document.getElementById("messages");

const sendHelloBtn = document.getElementById("sendHello");
const sendThanksBtn = document.getElementById("sendThanks");
const sendHelpBtn = document.getElementById("sendHelp");
const clearBtn = document.getElementById("clearBtn");

const emojiRow = document.getElementById("emojiRow");
const stickerGrid = document.getElementById("stickerGrid");

// State
let ws = null;
let myId = randId();
myIdEl.value = myId;

let roomId = "";
let peerId = "";

// E2EE state
let ecdhKeyPair = null;
let myPubJwk = null;
let peerPubJwk = null;
let aesKey = null;

function setStatus(s) { statusEl.textContent = s; }
function setCryptoState(s) { cryptoStateEl.textContent = s; }

function addBubble(text, who, meta="") {
  const wrap = document.createElement("div");
  wrap.style.display = "flex";
  wrap.style.flexDirection = "column";

  const b = document.createElement("div");
  b.className = `bubble ${who}`;
  b.textContent = text;

  const m = document.createElement("div");
  m.className = "meta";
  m.textContent = meta;

  wrap.appendChild(b);
  wrap.appendChild(m);
  messagesEl.appendChild(wrap);
  messagesEl.scrollTop = messagesEl.scrollHeight;
}

// -------- Crypto (WebCrypto) --------
async function ensureKeyPair() {
  if (ecdhKeyPair) return;
  ecdhKeyPair = await crypto.subtle.generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    true,
    ["deriveKey"]
  );
  myPubJwk = await crypto.subtle.exportKey("jwk", ecdhKeyPair.publicKey);
}

async function importPeerPublicKey(jwk) {
  return await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "ECDH", namedCurve: "P-256" },
    true,
    []
  );
}

async function deriveAesKey(peerPublicKey) {
  return await crypto.subtle.deriveKey(
    { name: "ECDH", public: peerPublicKey },
    ecdhKeyPair.privateKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptJson(obj) {
  if (!aesKey) throw new Error("E2EE not ready");
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = new TextEncoder().encode(JSON.stringify(obj));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, plain);
  return { iv_b64: b64encode(iv), ct_b64: b64encode(ct) };
}

async function decryptJson(iv_b64, ct_b64) {
  if (!aesKey) throw new Error("E2EE not ready");
  const iv = new Uint8Array(b64decode(iv_b64));
  const ct = b64decode(ct_b64);
  const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, aesKey, ct);
  const txt = new TextDecoder().decode(plainBuf);
  return JSON.parse(txt);
}

// -------- Networking --------
function wsUrl() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${location.host}/ws`;
}

function send(obj) {
  if (!ws || ws.readyState !== 1) return;
  ws.send(JSON.stringify(obj));
}

async function connect() {
  roomId = roomEl.value.trim();
  if (!roomId) return alert("Enter Room ID");

  ws = new WebSocket(wsUrl());

  ws.onopen = () => {
    setStatus("Connected (no E2EE yet)");
    send({ type: "join", room: roomId, client_id: myId });
    handshakeBtn.disabled = false;
  };

  ws.onclose = () => {
    setStatus("Disconnected");
    setCryptoState("E2EE: not ready");
    aesKey = null;
    peerPubJwk = null;
    handshakeBtn.disabled = true;
  };

  ws.onerror = () => setStatus("Connection error");

  ws.onmessage = async (ev) => {
    const msg = JSON.parse(ev.data);

    if (msg.type === "joined") {
      addBubble(`Joined room: ${msg.room}`, "them", nowTime());
      return;
    }

    if (msg.type === "roster") {
      rosterEl.textContent = `In room: ${msg.clients.join(", ")}`;
      return;
    }

    // NEW: history from MySQL (ciphertext)
    if (msg.type === "history") {
      addBubble(`Loaded history (${msg.messages.length})`, "them", nowTime());
      // Try render as "locked" until E2EE ready
      for (const h of msg.messages) {
        // If E2EE ready, decrypt; otherwise show placeholder
        if (!aesKey) {
          addBubble("🔒 Encrypted message (handshake to decrypt history)", "them", `${h.from} • ${h.created_at}`);
          continue;
        }
        await renderCipherAsBubble(h.from, h.iv, h.ciphertext, h.created_at);
      }
      return;
    }

    if (msg.type === "pubkey") {
      if (msg.to !== myId) return;
      peerPubJwk = msg.pubkey_jwk;

      await ensureKeyPair();
      const peerKey = await importPeerPublicKey(peerPubJwk);
      aesKey = await deriveAesKey(peerKey);

      setCryptoState("E2EE: ready ✅");
      addBubble("E2EE handshake complete.", "them", nowTime());

      return;
    }

    if (msg.type === "cipher") {
      if (msg.to !== myId) return;
      await renderCipherAsBubble(msg.from, msg.iv, msg.ciphertext, nowTime());
      return;
    }
  };
}

async function startHandshake() {
  peerId = peerIdEl.value.trim();
  if (!peerId) return alert("Paste Peer ID first");

  await ensureKeyPair();

  send({
    type: "pubkey",
    room: roomId,
    from: myId,
    to: peerId,
    pubkey_jwk: myPubJwk
  });

  setCryptoState("E2EE: waiting for peer…");
  addBubble("Sent my public key. Waiting for peer…", "me", nowTime());
}

async function sendEncrypted(payloadObj, msgTypeForDB) {
  peerId = peerIdEl.value.trim();
  if (!peerId) return alert("Set Peer ID");
  if (!aesKey) return alert("E2EE not ready. Click Start E2EE Handshake on both sides.");

  const { iv_b64, ct_b64 } = await encryptJson(payloadObj);

  // msg_type is NOT sensitive; DB metadata only
  send({
    type: "cipher",
    room: roomId,
    from: myId,
    to: peerId,
    iv: iv_b64,
    ciphertext: ct_b64,
    msg_type: msgTypeForDB || "unknown"
  });
}

async function renderCipherAsBubble(fromId, iv_b64, ct_b64, timeLabel) {
  try {
    const obj = await decryptJson(iv_b64, ct_b64);

    if (obj.type === "emoji") {
      addBubble(obj.value, "them", `${fromId} • ${timeLabel}`);
    } else if (obj.type === "sticker") {
      addBubble(`🧏 Sticker: ${obj.id} ${obj.icon || ""}`, "them", `${fromId} • ${timeLabel}`);
    } else {
      addBubble("(unknown message)", "them", `${fromId} • ${timeLabel}`);
    }
  } catch {
    addBubble("⚠️ Could not decrypt (wrong key?)", "them", `${fromId} • ${timeLabel}`);
  }
}

// -------- Emoji + Stickers --------
const EMOJIS = ["😀","😂","🥹","😡","😴","❤️","✅","❌","🙏","🆘","❓","👋","👍","👎","🎉","🤝"];
const STICKERS = [
  { id: "hello", icon: "👋" },
  { id: "thanks", icon: "🙏" },
  { id: "yes", icon: "✅" },
  { id: "no", icon: "❌" },
  { id: "help", icon: "🆘" },
  { id: "question", icon: "❓" },
  { id: "wait", icon: "⏱️" },
  { id: "where", icon: "📍" }
];

function initButtons() {
  for (const e of EMOJIS) {
    const btn = document.createElement("button");
    btn.className = "emojiBtn";
    btn.textContent = e;
    btn.onclick = async () => {
      await sendEncrypted({ type: "emoji", value: e, ts: Date.now() }, "emoji");
      addBubble(e, "me", `${myId} • ${nowTime()}`);
    };
    emojiRow.appendChild(btn);
  }

  for (const s of STICKERS) {
    const btn = document.createElement("button");
    btn.className = "stickerBtn";
    btn.textContent = s.icon;
    btn.title = s.id;
    btn.onclick = async () => {
      await sendEncrypted({ type: "sticker", id: s.id, icon: s.icon, ts: Date.now() }, "sticker");
      addBubble(`🧏 Sticker: ${s.id} ${s.icon}`, "me", `${myId} • ${nowTime()}`);
    };
    stickerGrid.appendChild(btn);
  }

  sendHelloBtn.onclick = async () => {
    await sendEncrypted({ type: "sticker", id: "hello", icon: "👋", ts: Date.now() }, "sticker");
    addBubble(`🧏 Sticker: hello 👋`, "me", `${myId} • ${nowTime()}`);
  };

  sendThanksBtn.onclick = async () => {
    await sendEncrypted({ type: "sticker", id: "thanks", icon: "🙏", ts: Date.now() }, "sticker");
    addBubble(`🧏 Sticker: thanks 🙏`, "me", `${myId} • ${nowTime()}`);
  };

  sendHelpBtn.onclick = async () => {
    await sendEncrypted({ type: "sticker", id: "help", icon: "🆘", ts: Date.now() }, "sticker");
    addBubble(`🧏 Sticker: help 🆘`, "me", `${myId} • ${nowTime()}`);
  };

  clearBtn.onclick = () => {
    messagesEl.innerHTML = "";
  };
}

connectBtn.onclick = connect;
handshakeBtn.onclick = startHandshake;

initButtons();
setStatus("Disconnected");
setCryptoState("E2EE: not ready");
