// ─────────────────────────────────────────────────────────────
//  Cloud-Lernstand fuer den Vokabeltrainer
//  Speichert je Profil (Name + PIN) den Uebungsstand dauerhaft in
//  Netlify Blobs. Keine personenbezogenen Daten - nur Lernfortschritt.
//
//  Endpunkt:  POST /.netlify/functions/sync
//  Aktionen:  { action:'login', user, pin, data? }   -> anmelden / Profil anlegen
//             { action:'save',  user, pin, data  }   -> Stand speichern
// ─────────────────────────────────────────────────────────────
import { getStore } from '@netlify/blobs';
import crypto from 'node:crypto';

const STORE = 'vokabel-progress';
const MAX_BYTES = 1_000_000; // Sicherheitsgrenze fuer die Datenmenge je Profil

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });
}

// Profil-Schluessel: Name normalisiert (klein, getrimmt) -> kollisionsarm & stabil
function normUser(u) {
  return String(u || '').trim().toLowerCase().slice(0, 60);
}

// PIN wird NICHT im Klartext gespeichert, sondern als Hash (Name+PIN)
function pinHash(user, pin) {
  return crypto.createHash('sha256').update(user + '::' + String(pin)).digest('hex');
}

export default async (req) => {
  if (req.method !== 'POST') return json({ ok: false, reason: 'method' }, 405);

  let payload;
  try { payload = await req.json(); }
  catch { return json({ ok: false, reason: 'badjson' }, 400); }

  const { action, pin, data } = payload || {};
  const user = normUser(payload && payload.user);

  if (!user) return json({ ok: false, reason: 'nouser' });
  if (pin === undefined || pin === null || String(pin).length < 1)
    return json({ ok: false, reason: 'nopin' });

  const store = getStore(STORE);
  let existing = null;
  try { existing = await store.get(user, { type: 'json' }); }
  catch { existing = null; }

  if (action === 'login') {
    if (!existing) {
      // Profil gibt es noch nicht -> neu anlegen, aktuellen lokalen Stand uebernehmen
      const rec = { pinHash: pinHash(user, pin), data: data || {}, updatedAt: Date.now() };
      await store.setJSON(user, rec);
      return json({ ok: true, created: true, data: rec.data });
    }
    if (existing.pinHash !== pinHash(user, pin))
      return json({ ok: false, reason: 'pin' }); // Name existiert, PIN falsch
    return json({ ok: true, created: false, data: existing.data || {} });
  }

  if (action === 'save') {
    if (!existing) return json({ ok: false, reason: 'notfound' });
    if (existing.pinHash !== pinHash(user, pin))
      return json({ ok: false, reason: 'pin' });
    const body = JSON.stringify(data || {});
    if (body.length > MAX_BYTES) return json({ ok: false, reason: 'toobig' });
    await store.setJSON(user, { pinHash: existing.pinHash, data: data || {}, updatedAt: Date.now() });
    return json({ ok: true });
  }

  return json({ ok: false, reason: 'action' });
};
