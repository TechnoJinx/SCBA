// acr1555u.js — Web Bluetooth driver for the ACS ACR1555U NFC reader.
// Protocol details taken from ACS's Android library (acssmcio 0.6.2):
//   GATT service 00003970-..., write 3971, response notify 3972, card notify 3973.
//   Mutual auth: AES-128, CBC, zero IV, default master key "ACR1555U-A1 Auth".
//   Messages are CCID (PC_to_RDR) wrapped in 0x55 ... checksum 0xAA frames.
// No dependencies. Needs Chrome on Android (Web Bluetooth) over https.

const SVC = '00003970-817c-48df-8db2-476a8134ede0';
const CH_WRITE = '00003971-817c-48df-8db2-476a8134ede0';
const CH_RESP = '00003972-817c-48df-8db2-476a8134ede0';
const CH_CARD = '00003973-817c-48df-8db2-476a8134ede0';
const BATTERY_SVC = 0x180f;
const BATTERY_LEVEL = 0x2a19;

const DEFAULT_KEY = new TextEncoder().encode('ACR1555U-A1 Auth');
const CHUNK = 11;           // payload bytes per BLE packet (11 + 9 framing = 20, fits default MTU)
const SLOT_PICC = 0;

// CCID message types
const PC_ICC_ON = 0x62, PC_ICC_OFF = 0x63, PC_SLOT_STATUS = 0x65, PC_ESCAPE = 0x6b, PC_XFR = 0x6f;

export const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0').toUpperCase()).join(' ');
export const fromHex = (s) => {
  const c = s.replace(/[^0-9a-f]/gi, '');
  if (c.length % 2) throw new Error('Odd number of hex digits');
  return Uint8Array.from(c.match(/../g) || [], (h) => parseInt(h, 16));
};
const concat = (...arrs) => {
  const out = new Uint8Array(arrs.reduce((n, a) => n + a.length, 0));
  let o = 0;
  for (const a of arrs) { out.set(a, o); o += a.length; }
  return out;
};
const xorSum = (b, from, count) => { let x = 0; for (let i = 0; i < count; i++) x ^= b[from + i]; return x; };

// ---- AES-128-CBC, zero IV, no padding, built on WebCrypto ----
const ZERO_IV = new Uint8Array(16);
async function importKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-CBC' }, false, ['encrypt', 'decrypt']);
}
// Input length must be a multiple of 16. WebCrypto always adds PKCS#7, so drop the extra block.
export async function cbcEncrypt(rawKey, data) {
  const key = await importKey(rawKey);
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, data));
  return out.slice(0, data.length);
}
// WebCrypto insists on valid PKCS#7 on decrypt, so append a forged final block that
// decrypts to a full padding block, then let WebCrypto strip it.
export async function cbcDecrypt(rawKey, data) {
  if (!data.length || data.length % 16) throw new Error('Ciphertext must be a multiple of 16 bytes');
  const key = await importKey(rawKey);
  const last = data.slice(data.length - 16);
  const pad = new Uint8Array(16).fill(16);
  const forged = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-CBC', iv: last }, key, pad)).slice(0, 16);
  const out = await crypto.subtle.decrypt({ name: 'AES-CBC', iv: ZERO_IV }, key, concat(data, forged));
  return new Uint8Array(out);
}
const zeroPad16 = (b) => { const n = Math.ceil(b.length / 16) * 16 || 16; const o = new Uint8Array(n); o.set(b); return o; };

export class ReaderError extends Error {}

export class ACR1555U extends EventTarget {
  constructor({ key = DEFAULT_KEY, log = () => {} } = {}) {
    super();
    this.key = key;
    this.log = log;
    this.device = null;
    this.cardPresent = false;
    this.battery = null;
    this._onRespEvt = (e) => this._onResp(new Uint8Array(e.target.value.buffer));
    this._onCardEvt = (e) => this._onCard(new Uint8Array(e.target.value.buffer));
    this._reset();
  }

  _reset() {
    this.authed = false;
    this.sessionKey = null;
    this.txSeq = 0;          // frame byte 5: our packet counter
    this.rxSeq = 0;          // frame byte 6: tracks reader's packet counter
    this.rxSeqFirst = true;
    this.ccidSeq = 0;
    this.rxBuf = [];
    this.rxLen = 0;
    this.waiters = [];
    this.queue = Promise.resolve();
  }

  get connected() { return !!(this.device && this.device.gatt.connected); }

  // Must be called from a user gesture (button tap).
  async connect() {
    if (!navigator.bluetooth) throw new ReaderError('Web Bluetooth not available. Use Chrome on Android over https.');
    const device = await navigator.bluetooth.requestDevice({
      filters: [{ namePrefix: 'ACR1555U' }],
      optionalServices: [SVC, BATTERY_SVC],
    });
    await this.useDevice(device);
  }

  // Reader this site was already given permission for (no picker needed), or null.
  // Chrome only supports this when its newer Bluetooth permissions are enabled.
  static async rememberedDevice() {
    if (!navigator.bluetooth || !navigator.bluetooth.getDevices) return null;
    try {
      const list = await navigator.bluetooth.getDevices();
      return list.find((d) => (d.name || '').startsWith('ACR1555U')) || null;
    } catch { return null; }
  }

  async useDevice(device) {
    if (this.device !== device) {
      this.device = device;
      device.addEventListener('gattserverdisconnected', () => {
        if (this.device !== device) return;
        this.log('Reader disconnected');
        this._failWaiters(new ReaderError('Reader disconnected'));
        this.cardPresent = false;
        this.dispatchEvent(new Event('disconnected'));
      });
    }
    await this._openGatt();
  }

  async reconnect() {
    if (!this.device) throw new ReaderError('No reader chosen yet');
    await this._openGatt();
  }

  async _openGatt() {
    this._reset();
    this.log(`Connecting to ${this.device.name}…`);
    const server = await this.device.gatt.connect();
    const svc = await server.getPrimaryService(SVC);
    this.chWrite = await svc.getCharacteristic(CH_WRITE);
    this.chResp = await svc.getCharacteristic(CH_RESP);
    this.chCard = await svc.getCharacteristic(CH_CARD);

    for (const [ch, fn] of [[this.chResp, this._onRespEvt], [this.chCard, this._onCardEvt]]) {
      ch.removeEventListener('characteristicvaluechanged', fn);
      ch.addEventListener('characteristicvaluechanged', fn);
    }
    await this.chResp.startNotifications();
    await this.chCard.startNotifications();

    try {
      const bsvc = await server.getPrimaryService(BATTERY_SVC);
      const bch = await bsvc.getCharacteristic(BATTERY_LEVEL);
      this.battery = (await bch.readValue()).getUint8(0);
      bch.addEventListener('characteristicvaluechanged', (e) => {
        this.battery = e.target.value.getUint8(0);
        this.dispatchEvent(new Event('battery'));
      });
      await bch.startNotifications().catch(() => {});
      this.dispatchEvent(new Event('battery'));
    } catch { /* battery service optional */ }

    await this._authenticate();
    await this._refreshCardState();
    this.log('Reader ready');
    this.dispatchEvent(new Event('ready'));
  }

  disconnect() { if (this.connected) this.device.gatt.disconnect(); }

  // ---------- authentication ----------
  async _authenticate() {
    const check = await this.escape(Uint8Array.of(0xe0, 0, 0, 0x77, 0));
    if (!(check.length > 5 && check[5] !== 0)) { this.log('Reader does not require authentication'); return; }

    this.log('Authenticating…');
    const r1 = await this.escape(Uint8Array.of(0xe0, 0, 0, 0x73, 0));
    if (r1.length < 21 || r1[0] !== 0xe1 || (r1[3] !== 0 && r1[3] !== 0x73) || r1[4] !== 16)
      throw new ReaderError('Auth step 1 failed: ' + hex(r1));
    const rndB = await cbcDecrypt(this.key, r1.slice(5, 21));
    const rndA = crypto.getRandomValues(new Uint8Array(16));
    const blob = await cbcDecrypt(this.key, concat(rndA, rndB));

    const r2 = await this.escape(concat(Uint8Array.of(0xe0, 0, 0, 0x74, 0), blob));
    if (r2.length < 21 || r2[0] !== 0xe1 || (r2[3] !== 0 && r2[3] !== 0x74) || r2[4] !== 16)
      throw new ReaderError('Auth step 2 failed (wrong master key?): ' + hex(r2));
    const echo = await cbcDecrypt(this.key, r2.slice(5, 21));
    if (hex(echo) !== hex(rndA)) throw new ReaderError('Reader failed authentication (wrong master key?)');

    this.sessionKey = concat(rndB.slice(0, 8), rndA.slice(0, 8));
    this.authed = true;
    this.log('Authenticated');
  }

  // ---------- card presence ----------
  _onCard(v) {
    if (v.length < 2 || v[0] !== 0x50) return;
    if (v[1] === 0x02) this._setCard(false);
    else if (v[1] === 0x03) this._setCard(true);
  }
  _setCard(present) {
    if (present === this.cardPresent) return;
    this.cardPresent = present;
    this.dispatchEvent(new Event(present ? 'cardpresent' : 'cardremoved'));
  }
  async _refreshCardState() {
    const r = await this._ccid(PC_SLOT_STATUS, SLOT_PICC, new Uint8Array(0), 0, { raw: true });
    const icc = r[7] & 3;
    this._setCard(icc === 0 || icc === 1);
  }

  // ---------- public commands ----------
  // Power the card and return its ATR.
  async powerOn() {
    await this._ccid(PC_ICC_OFF, SLOT_PICC, new Uint8Array(0), 0);
    await new Promise((r) => setTimeout(r, 10));
    return this._ccid(PC_ICC_ON, SLOT_PICC, new Uint8Array(0), 0);
  }
  powerOff() { return this._ccid(PC_ICC_OFF, SLOT_PICC, new Uint8Array(0), 0); }

  // Send an APDU (Uint8Array or hex string), returns response bytes incl. SW1 SW2.
  async transmit(apdu) {
    if (typeof apdu === 'string') apdu = fromHex(apdu);
    return this._ccid(PC_XFR, SLOT_PICC, apdu, 0);
  }

  // Reader escape command (same as BLE Test app "Control" with code 3500).
  escape(data) {
    if (typeof data === 'string') data = fromHex(data);
    return this._ccid(PC_ESCAPE, SLOT_PICC, data, 0);
  }

  // Convenience: power on and read the tag UID. Returns { uid, atr }.
  async readUid() {
    const atr = await this.powerOn();
    const r = await this.transmit(Uint8Array.of(0xff, 0xca, 0, 0, 0));
    const sw = (r[r.length - 2] << 8) | r[r.length - 1];
    if (sw !== 0x9000) throw new ReaderError('Get UID failed, status ' + sw.toString(16).toUpperCase());
    return { uid: r.slice(0, -2), atr };
  }

  // Read binary: NTAG/Ultralight page or ISO 15693 block. Returns data without SW.
  async readBinary(addr, len) {
    const r = await this.transmit(Uint8Array.of(0xff, 0xb0, (addr >> 8) & 0xff, addr & 0xff, len));
    if (r.length < 2 || r[r.length - 2] !== 0x90 || r[r.length - 1] !== 0) throw new ReaderError('Read failed at ' + addr);
    return r.slice(0, -2);
  }

  // Full read: UID plus any NDEF records on the tag. Never throws for NDEF problems —
  // a tag without readable NDEF just comes back with records: [].
  // Returns { uid, serialNumber, atr, records: [{ recordType, data, encoding, lang }], texts: [..] }
  async readTag() {
    const { uid, atr } = await this.readUid();
    let ndef = null;
    try { ndef = await this._readNdefType2(); } catch { /* not a Type 2 tag */ }
    if (!ndef) { try { ndef = await this._readNdefType5(); } catch { /* not a Type 5 tag */ } }
    let records = [];
    if (ndef) { try { records = parseNdef(ndef); } catch (e) { this.log('NDEF parse failed: ' + e.message); } }
    const texts = records.filter((r) => r.recordType === 'text').map((r) => r.text.trim());
    return { uid, serialNumber: uidToSerial(uid), atr, records, texts };
  }

  // NTAG / MIFARE Ultralight (NFC Forum Type 2): CC on page 3, data from page 4, 4-byte pages.
  async _readNdefType2() {
    const first = await this.readBinary(3, 16);            // page 3 (CC) + pages 4-6
    if (first.length < 16 || first[0] !== 0xe1) return null;
    const area = Math.min(first[2] * 8, 2048);
    let data = first.slice(4);
    const tlv = () => findNdefTlv(data);
    let page = 7;
    while (tlv() === undefined && data.length < area) {
      data = concat(data, await this.readBinary(page, 16));
      page += 4;
    }
    return tlv() || null;
  }

  // ISO 15693 (NFC Forum Type 5): CC in block 0 (4 or 8 bytes), 4-byte blocks.
  async _readNdefType5() {
    const b0 = await this.readBinary(0, 4);
    if (b0.length !== 4 || (b0[0] !== 0xe1 && b0[0] !== 0xe2)) return null;
    let block = 1, data = new Uint8Array(0), area = b0[2] * 8;
    if (b0[2] === 0) {                                      // 8-byte CC: size in bytes 6-7
      const b1 = await this.readBinary(1, 4);
      area = ((b1[2] << 8) | b1[3]) * 8;
      block = 2;
    }
    area = Math.min(area, 2048);
    while (findNdefTlv(data) === undefined && data.length < area) {
      data = concat(data, await this.readBinary(block++, 4));
    }
    return findNdefTlv(data) || null;
  }

  // ---------- CCID layer ----------
  _ccid(type, slot, data, param, opts = {}) {
    const run = async () => {
      const seq = this.ccidSeq; this.ccidSeq = (this.ccidSeq + 1) & 0xff;
      const n = data.length;
      const msg = new Uint8Array(10 + n);
      msg[0] = type;
      msg[1] = n & 0xff; msg[2] = (n >> 8) & 0xff; msg[3] = (n >> 16) & 0xff; msg[4] = (n >>> 24) & 0xff;
      msg[5] = slot; msg[6] = seq; msg[7] = 0; msg[8] = param; msg[9] = 0;
      msg.set(data, 10);
      const resp = await this._exchange(slot, msg, seq);
      return opts.raw ? resp : resp.slice(10);
    };
    const p = this.queue.then(run, run);
    this.queue = p.catch(() => {});
    return p;
  }

  async _exchange(slot, msg, seq, timeoutMs = 10000) {
    if (!this.connected) throw new ReaderError('Reader not connected');
    const enc = this.authed;
    const payload = enc ? await cbcEncrypt(this.sessionKey, zeroPad16(msg)) : msg;

    let waitFor = this._nextMessage(timeoutMs);
    for (let off = 0; off < payload.length; off += CHUNK) {
      const chunk = payload.slice(off, off + CHUNK);
      const e = chunk.length;
      const pkt = new Uint8Array(e + 9);
      pkt[0] = 0x55;
      pkt[1] = enc ? 1 : 0;
      pkt[2] = (payload.length >> 8) & 0xff;
      pkt[3] = payload.length & 0xff;
      pkt[4] = slot;
      pkt[5] = this.txSeq;
      pkt[6] = this.rxSeq;
      pkt.set(chunk, 7);
      pkt[e + 7] = xorSum(pkt, 1, e + 6);
      pkt[e + 8] = 0xaa;
      await this._write(pkt);
      this.txSeq = (this.txSeq + 1) & 0xff;
    }

    let tries = 10;
    for (;;) {
      const r = await waitFor;
      if (r.length > 0 && r[0] === 0x53 && r.length > 8) throw new ReaderError('Reader error 0x' + r[8].toString(16));
      if (r.length > 0 && r[0] === 0x51 && r.length > 7) throw new ReaderError('Reader error 0x' + r[7].toString(16));
      if (r.length < 10) throw new ReaderError('Invalid response length: ' + r.length);
      if (r[6] !== seq) {
        if (--tries <= 0) throw new ReaderError(`Invalid sequence number: ${r[6]} (${seq})`);
        waitFor = this._nextMessage(timeoutMs);
        continue;
      }
      const cmdStatus = (r[7] >> 6) & 3;
      const icc = r[7] & 3;
      const err = r[8];
      if (cmdStatus === 2) { // time extension
        waitFor = this._nextMessage(timeoutMs * Math.max(1, err));
        continue;
      }
      if (cmdStatus === 1) {
        if (msg[0] === 0x61 && err <= 127) return r;
        if (err === 0xfe) {
          if (icc === 2) { this._setCard(false); throw new ReaderError('No card present'); }
          throw new ReaderError('Card did not respond (ICC mute)');
        }
        throw new ReaderError('Command failed, error 0x' + err.toString(16));
      }
      return r;
    }
  }

  async _write(pkt) {
    const props = this.chWrite.properties;
    if (props.write && this.chWrite.writeValueWithResponse) await this.chWrite.writeValueWithResponse(pkt);
    else if (this.chWrite.writeValueWithoutResponse) await this.chWrite.writeValueWithoutResponse(pkt);
    else await this.chWrite.writeValue(pkt);
  }

  _nextMessage(timeoutMs) {
    return new Promise((resolve, reject) => {
      const w = { resolve, reject };
      w.timer = setTimeout(() => {
        this.waiters = this.waiters.filter((x) => x !== w);
        reject(new ReaderError('Reader did not respond (timeout)'));
      }, timeoutMs);
      this.waiters.push(w);
    });
  }
  _failWaiters(err) {
    const ws = this.waiters; this.waiters = [];
    for (const w of ws) { clearTimeout(w.timer); w.reject(err); }
  }

  // Incoming frame: 55 flag lenHi lenLo slot seqA seqB data… xor AA
  async _onResp(v) {
    const start = v.indexOf(0x55);
    if (start < 0) { this.rxBuf = []; this.rxLen = 0; return; }
    const f = v.slice(start);
    const n = f.length;
    if (n < 10) return;
    const total = (f[2] << 8) | f[3];
    if (xorSum(f, 1, n - 3) !== f[n - 2]) { this.log('Dropped frame with bad checksum'); return; }
    if (this.rxSeqFirst) { this.rxSeq = f[6]; this.rxSeqFirst = false; }
    else if (this.rxSeq !== f[6]) { this.log('Dropped out-of-order frame'); return; }
    this.rxSeq = (this.rxSeq + 1) & 0xff;

    for (const b of f.slice(7, n - 2)) this.rxBuf.push(b);
    if (this.rxBuf.length !== total) return;

    let msg = Uint8Array.from(this.rxBuf);
    this.rxBuf = [];
    try {
      if (this.authed) {
        msg = await cbcDecrypt(this.sessionKey, msg);
        const len = (msg[1] | (msg[2] << 8) | (msg[3] << 16) | (msg[4] << 24)) + 10;
        msg = msg.slice(0, len);
      }
    } catch (e) { this.log('Decrypt failed: ' + e.message); return; }

    const w = this.waiters.shift();
    if (w) { clearTimeout(w.timer); w.resolve(msg); }
  }
}

// Format a UID the way Web NFC's serialNumber does ("04:a1:b2:…"), so the same
// IDs match whether a tag was scanned with the phone or the reader.
export const uidToSerial = (uid) => Array.from(uid, (x) => x.toString(16).padStart(2, '0')).join(':');

// Find the NDEF message TLV (type 0x03) in a Type 2/5 data area.
// Returns the message bytes, null if the area has no NDEF TLV, or undefined if more bytes are needed.
export function findNdefTlv(d) {
  let i = 0;
  while (i < d.length) {
    const t = d[i];
    if (t === 0x00) { i++; continue; }           // NULL TLV
    if (t === 0xfe) return null;                 // terminator before any NDEF
    if (i + 1 >= d.length) return undefined;
    let len = d[i + 1], hdr = 2;
    if (len === 0xff) {
      if (i + 3 >= d.length) return undefined;
      len = (d[i + 2] << 8) | d[i + 3]; hdr = 4;
    }
    if (i + hdr + len > d.length) return undefined;
    if (t === 0x03) return d.slice(i + hdr, i + hdr + len);
    i += hdr + len;                              // lock/memory control or proprietary TLV
  }
  return undefined;
}

// Minimal NDEF parser shaped like Web NFC's records: text and URL records decoded, others raw.
export function parseNdef(m) {
  const out = [];
  let i = 0;
  while (i < m.length) {
    const h = m[i++];
    const sr = h & 0x10, il = h & 0x08, tnf = h & 0x07;
    const typeLen = m[i++];
    let payLen;
    if (sr) payLen = m[i++];
    else { payLen = ((m[i] << 24) | (m[i + 1] << 16) | (m[i + 2] << 8) | m[i + 3]) >>> 0; i += 4; }
    const idLen = il ? m[i++] : 0;
    const type = new TextDecoder().decode(m.slice(i, i + typeLen)); i += typeLen;
    i += idLen;
    const payload = m.slice(i, i + payLen); i += payLen;
    if (i > m.length) throw new Error('Truncated NDEF record');

    const rec = { recordType: 'unknown', data: payload };
    if (tnf === 1 && type === 'T' && payload.length) {
      const utf16 = payload[0] & 0x80, langLen = payload[0] & 0x3f;
      rec.recordType = 'text';
      rec.lang = new TextDecoder().decode(payload.slice(1, 1 + langLen));
      rec.encoding = utf16 ? 'utf-16' : 'utf-8';
      rec.text = new TextDecoder(rec.encoding).decode(payload.slice(1 + langLen));
    } else if (tnf === 1 && type === 'U') {
      rec.recordType = 'url';
    } else if (tnf === 0) {
      rec.recordType = 'empty';
    }
    out.push(rec);
    if (h & 0x40) break;                          // ME: last record
  }
  return out;
}
