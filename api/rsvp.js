// RSVP — Baile de Máscaras · Lorena 31
// POST   /api/rsvp            -> grava uma confirmação (Vercel Blob privado)
// GET    /api/rsvp            -> lista (requer header x-admin-password)
// DELETE /api/rsvp?id=<path>  -> remove uma confirmação (requer header x-admin-password)
import { put, list, get, del } from '@vercel/blob';
import crypto from 'node:crypto';

const PREFIX = 'rsvp/';
const json = (res, code, obj) => { res.statusCode = code; res.setHeader('Content-Type', 'application/json; charset=utf-8'); res.setHeader('Cache-Control', 'no-store'); res.end(JSON.stringify(obj)); };
const clean = (v, max) => String(v ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
const storageOk = () => !!(process.env.BLOB_READ_WRITE_TOKEN || (process.env.BLOB_STORE_ID && process.env.VERCEL_OIDC_TOKEN));

function isAdmin(req) {
  const pw = process.env.ADMIN_PASSWORD || '';
  const got = String(req.headers['x-admin-password'] || '');
  if (!pw || !got) return false;
  const a = crypto.createHash('sha256').update(pw).digest();
  const b = crypto.createHash('sha256').update(got).digest();
  return crypto.timingSafeEqual(a, b);
}
async function readBody(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  let raw = '';
  for await (const ch of req) { raw += ch; if (raw.length > 20000) break; }
  try { return JSON.parse(raw || '{}'); } catch { return {}; }
}
async function streamToText(stream) {
  const reader = stream.getReader(); const dec = new TextDecoder(); let out = '';
  for (;;) { const { done, value } = await reader.read(); if (done) break; out += dec.decode(value, { stream: true }); }
  return out + dec.decode();
}

export default async function handler(req, res) {
  try {
    if (req.method === 'POST') {
      if (!storageOk()) return json(res, 503, { ok: false, error: 'storage_not_configured' });
      const b = await readBody(req);
      if (clean(b.empresa, 100)) return json(res, 200, { ok: true }); // honeypot: finge sucesso
      const nome = clean(b.nome, 120);
      const telefone = clean(b.telefone, 30);
      const digits = telefone.replace(/\D/g, '');
      const vai = b.vai === 'nao' ? 'nao' : 'sim';
      let pessoas = parseInt(b.pessoas, 10); if (!Number.isFinite(pessoas) || pessoas < 1) pessoas = 1; if (pessoas > 20) pessoas = 20;
      if (vai === 'nao') pessoas = 0;
      const acompanhantes = vai === 'sim' ? clean(b.acompanhantes, 600) : '';
      const mensagem = clean(b.mensagem, 1000);
      const errors = {};
      if (nome.length < 3 || !/\s/.test(nome)) errors.nome = 'Informe seu nome completo.';
      if (digits.length < 10 || digits.length > 13) errors.telefone = 'Informe um telefone/WhatsApp válido.';
      if (Object.keys(errors).length) return json(res, 400, { ok: false, errors });
      const now = new Date();
      const entry = {
        nome, telefone, vai, pessoas, acompanhantes, mensagem,
        criadoEm: now.toISOString(),
        criadoEmBR: now.toLocaleString('pt-BR', { timeZone: 'America/Sao_Paulo' }),
        ua: clean(req.headers['user-agent'], 200)
      };
      const id = `${PREFIX}${now.toISOString().replace(/[:.]/g, '-')}-${crypto.randomBytes(5).toString('hex')}.json`;
      await put(id, JSON.stringify(entry), { access: 'private', contentType: 'application/json', addRandomSuffix: false });
      return json(res, 200, { ok: true });
    }
    if (req.method === 'GET') {
      if (!isAdmin(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
      if (!storageOk()) return json(res, 503, { ok: false, error: 'storage_not_configured' });
      const blobs = []; let cursor;
      do { const r = await list({ prefix: PREFIX, cursor, limit: 1000 }); blobs.push(...r.blobs); cursor = r.hasMore ? r.cursor : undefined; } while (cursor);
      const items = (await Promise.all(blobs.map(async (bl) => {
        try { const g = await get(bl.pathname, { access: 'private', useCache: false }); if (!g || !g.stream) return null; return { id: bl.pathname, ...JSON.parse(await streamToText(g.stream)) }; } catch { return null; }
      }))).filter(Boolean).sort((a, b) => (a.criadoEm < b.criadoEm ? 1 : -1));
      return json(res, 200, { ok: true, items });
    }
    if (req.method === 'DELETE') {
      if (!isAdmin(req)) return json(res, 401, { ok: false, error: 'unauthorized' });
      const id = String((req.query && req.query.id) || new URL(req.url, 'http://x').searchParams.get('id') || '');
      if (!id.startsWith(PREFIX) || id.includes('..')) return json(res, 400, { ok: false, error: 'bad_id' });
      await del(id);
      return json(res, 200, { ok: true });
    }
    res.setHeader('Allow', 'GET, POST, DELETE');
    return json(res, 405, { ok: false, error: 'method_not_allowed' });
  } catch (e) {
    console.error('rsvp error', e);
    return json(res, 500, { ok: false, error: 'server_error' });
  }
}
