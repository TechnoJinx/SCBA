// cloud-sync.js — optional Firebase (Firestore + Google sign-in) sync for the Safety Equipment Tracker.
// Loaded on demand by index.html; the app works fully without it (local-only).
//
// What syncs:   equipment records (collection "scba_items") and component movement history
//               (collection "scba_history"). Monthly archives and the calibration registry stay local.
// How:          one Firestore document per record. Edits on any phone appear on the others in near real
//               time. Firestore's own offline cache queues writes made without signal.
// Access:       Google sign-in + Firestore security rules (see SCBA_Cloud_Setup.md) decide who is allowed in.

const FIREBASE_VERSION = '10.12.2';
const CDN = `https://www.gstatic.com/firebasejs/${FIREBASE_VERSION}/`;
const ITEMS_COL = 'scba_items';
const HISTORY_COL = 'scba_history';
const BASE_KEY = 'safety_tracker_cloud_base_v1';   // id -> hash of the record as last synced
const DELETE_CONFIRM_THRESHOLD = 25;

function hash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = ((h << 5) + h + str.charCodeAt(i)) | 0;
  return h;
}
const encId = (id) => encodeURIComponent(id);
const histLen = (it) => (it && Array.isArray(it.history)) ? it.history.length : 0;
const entryKey = (e) => `${e.collectionPointId}|${e.role}|${e.timestamp}`;

function mergeEntries(a, b) {
  const seen = new Map();
  [...(a || []), ...(b || [])].forEach((e) => { if (e && !seen.has(entryKey(e))) seen.set(entryKey(e), e); });
  return Array.from(seen.values()).sort((x, y) => (Number(x.timestamp) || 0) - (Number(y.timestamp) || 0));
}

export function createCloudSync({ bridge, hooks, onStatus }) {
  let fb = null, auth = null, db = null, user = null;
  let unsubs = [];
  let base = {};                       // id -> hash, persisted
  try { base = JSON.parse(localStorage.getItem(BASE_KEY) || '{}'); } catch { base = {}; }
  const saveBase = () => { try { localStorage.setItem(BASE_KEY, JSON.stringify(base)); } catch { /* quota */ } };

  const remoteItems = new Map();       // id -> json string currently in the cloud
  const remoteHist = new Map();        // key -> json string currently in the cloud
  let itemsReady = false, histReady = false;   // first *server* snapshot received
  let pushTimer = null, pushing = false, pushAgain = false;
  let lastSyncAt = null;

  const status = (state, text) => { try { onStatus && onStatus(state, text); } catch { /* ignore */ } };

  // ---------- startup ----------
  async function start(config) {
    status('loading', 'Loading cloud sync…');
    try {
      const [appMod, authMod, fsMod] = await Promise.all([
        import(CDN + 'firebase-app.js'), import(CDN + 'firebase-auth.js'), import(CDN + 'firebase-firestore.js')
      ]);
      fb = { ...appMod, ...authMod, ...fsMod };
    } catch (err) {
      status('error', 'Could not load Firebase (offline, or blocked). Working locally.');
      return;
    }
    try {
      const app = fb.initializeApp(config);
      auth = fb.getAuth(app);
      try {
        db = fb.initializeFirestore(app, { localCache: fb.persistentLocalCache({ tabManager: fb.persistentMultipleTabManager() }) });
      } catch { db = fb.getFirestore(app); }
    } catch (err) {
      status('error', 'Firebase config problem: ' + (err && err.message || err));
      return;
    }
    fb.onAuthStateChanged(auth, (u) => {
      user = u;
      if (u) attach(); else { detach(); status('signedout', 'Not signed in'); }
    });
  }

  async function signIn() {
    if (!auth) throw new Error('Cloud sync is not loaded yet');
    const provider = new fb.GoogleAuthProvider();
    provider.setCustomParameters({ prompt: 'select_account' });
    await fb.signInWithPopup(auth, provider);
  }
  async function signInEmail(email, password) {
    if (!auth) throw new Error('Cloud sync is not loaded yet');
    await fb.signInWithEmailAndPassword(auth, String(email || '').trim(), String(password || ''));
  }
  async function signOut() {
    detach();
    if (auth) await fb.signOut(auth);
  }

  // ---------- attach / detach listeners ----------
  function attach() {
    detach();
    itemsReady = false; histReady = false;
    status('connecting', 'Signed in as ' + user.email + ' — syncing…');
    const onErr = (err) => {
      if (err && err.code === 'permission-denied') status('error', user.email + ' is not approved for this data. Ask the owner to add it in the Firestore rules.');
      else status('error', 'Sync error: ' + (err && err.message || err));
    };
    unsubs.push(fb.onSnapshot(fb.collection(db, ITEMS_COL), { includeMetadataChanges: false }, onItemsSnapshot, onErr));
    unsubs.push(fb.onSnapshot(fb.collection(db, HISTORY_COL), { includeMetadataChanges: false }, onHistorySnapshot, onErr));
    hooks.onItemsSaved = schedulePush;
    hooks.onHistorySaved = schedulePush;
  }
  function detach() {
    unsubs.forEach((u) => { try { u(); } catch { /* ignore */ } });
    unsubs = [];
    hooks.onItemsSaved = null;
    hooks.onHistorySaved = null;
    itemsReady = false; histReady = false;
  }

  // ---------- pull: cloud -> this phone ----------
  function onItemsSnapshot(snap) {
    const local = bridge.getItems();
    const upserts = {}, removals = [];
    snap.docChanges().forEach((ch) => {
      const d = ch.doc;
      if (d.metadata.hasPendingWrites) return;                 // our own write coming back
      const data = d.data() || {};
      const id = data.id;
      if (id === undefined) return;
      if (ch.type === 'removed') {
        remoteItems.delete(id);
        delete base[id];
        if (id in local) removals.push(id);
        return;
      }
      const json = data.data;
      remoteItems.set(id, json);
      let remote;
      try { remote = JSON.parse(json); } catch { return; }
      const mine = local[id];
      if (mine === undefined) { upserts[id] = remote; base[id] = hash(json); return; }
      const mineJson = JSON.stringify(mine);
      if (mineJson === json) { base[id] = hash(json); return; }
      // Differs. Keep the local copy only if it has unsynced edits of its own.
      const dirty = (id in base) ? (hash(mineJson) !== base[id]) : (histLen(mine) > histLen(remote));
      if (!dirty) { upserts[id] = remote; base[id] = hash(json); }
    });
    const n = bridge.applyItems(upserts, removals);
    saveBase();
    if (!snap.metadata.fromCache) {
      itemsReady = true;
      lastSyncAt = Date.now();
      if (histReady) status('synced', 'Synced as ' + user.email);
      schedulePush(0);
    }
    if (n && !snap.metadata.fromCache) bridge.toast('☁️ ' + n + ' update' + (n === 1 ? '' : 's') + ' from other devices');
  }

  function onHistorySnapshot(snap) {
    const incoming = {};
    snap.docChanges().forEach((ch) => {
      if (ch.type === 'removed') { remoteHist.delete(ch.doc.data().key); return; }
      const data = ch.doc.data() || {};
      if (data.key === undefined) return;
      remoteHist.set(data.key, data.data);
      try { incoming[data.key] = JSON.parse(data.data); } catch { /* skip */ }
    });
    bridge.mergeHistory(incoming);
    if (!snap.metadata.fromCache) {
      histReady = true;
      if (itemsReady) status('synced', 'Synced as ' + user.email);
      schedulePush(0);
    }
  }

  // ---------- push: this phone -> cloud ----------
  function schedulePush(delay = 800) {
    if (typeof delay !== 'number') delay = 800;
    clearTimeout(pushTimer);
    pushTimer = setTimeout(pushNow, delay);
  }

  async function pushNow() {
    if (!user || !itemsReady || !histReady) return;            // wait until we know what the cloud has
    if (pushing) { pushAgain = true; return; }
    pushing = true;
    try {
      const ops = [];
      const items = bridge.getItems();
      const email = user.email || '';

      for (const [id, item] of Object.entries(items)) {
        const json = JSON.stringify(item);
        if (remoteItems.get(id) === json) { base[id] = hash(json); continue; }
        ops.push({ kind: 'set', ref: fb.doc(db, ITEMS_COL, encId(id)), data: { id, data: json, updatedAt: Date.now(), by: email },
          after: () => { remoteItems.set(id, json); base[id] = hash(json); } });
      }

      // Deletions: only for records this device has synced before and that are now gone locally.
      const gone = [];
      for (const id of remoteItems.keys()) if (!(id in items) && (id in base)) gone.push(id);
      if (gone.length > DELETE_CONFIRM_THRESHOLD && !bridge.confirm(
        `This will delete ${gone.length} records from the cloud for EVERYONE using the app. Continue?\n\n(Cancel restores them on this phone.)`)) {
        const restore = {};
        gone.forEach((id) => { try { restore[id] = JSON.parse(remoteItems.get(id)); } catch { /* skip */ } });
        bridge.applyItems(restore, []);
      } else {
        gone.forEach((id) => ops.push({ kind: 'delete', ref: fb.doc(db, ITEMS_COL, encId(id)),
          after: () => { remoteItems.delete(id); delete base[id]; } }));
      }

      // History: union local + cloud, push when the merged result differs from the cloud copy.
      const hist = bridge.getHistory();
      for (const [key, entries] of Object.entries(hist)) {
        const json = JSON.stringify(entries);
        if (remoteHist.get(key) === json) continue;
        ops.push({ kind: 'set', ref: fb.doc(db, HISTORY_COL, encId(key)), data: { key, data: json, updatedAt: Date.now(), by: email },
          after: () => { remoteHist.set(key, json); } });
      }

      for (let i = 0; i < ops.length; i += 400) {
        const chunk = ops.slice(i, i + 400);
        const batch = fb.writeBatch(db);
        chunk.forEach((op) => op.kind === 'set' ? batch.set(op.ref, op.data) : batch.delete(op.ref));
        await batch.commit();
        chunk.forEach((op) => op.after());
      }
      if (ops.length) { saveBase(); lastSyncAt = Date.now(); status('synced', 'Synced as ' + user.email); }
    } catch (err) {
      status('error', 'Upload failed: ' + (err && err.message || err) + ' — will retry on the next change.');
    } finally {
      pushing = false;
      if (pushAgain) { pushAgain = false; schedulePush(); }
    }
  }

  return {
    start, signIn, signInEmail, signOut,
    syncNow: () => pushNow(),
    get user() { return user; },
    get lastSyncAt() { return lastSyncAt; },
  };
}

export { mergeEntries };
