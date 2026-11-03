import crypto from 'crypto';

const ALLOWED_MODELS = new Set(['gemini-2.5-flash', 'gemini-2.5-flash-image-preview']);

// Rate limit sederhana per IP (per instance serverless).
// Untuk proteksi yang lebih kuat di production, gunakan Upstash Redis.
const WINDOW_MS = 60_000;
const MAX_REQ_PER_WINDOW = 40;
const hits = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  if (hits.size > 5000) hits.clear();
  const entry = hits.get(ip);
  if (!entry || now - entry.start > WINDOW_MS) {
    hits.set(ip, { start: now, count: 1 });
    return false;
  }
  entry.count += 1;
  return entry.count > MAX_REQ_PER_WINDOW;
}

// Bandingkan hash SHA-256 agar panjang kode tidak bocor lewat timing
function safeEqual(a, b) {
  const ha = crypto.createHash('sha256').update(String(a)).digest();
  const hb = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(ha, hb);
}

function getIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket?.remoteAddress || 'unknown';
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  // Rate limit dicek dulu, termasuk untuk percobaan login yang gagal
  if (isRateLimited(getIp(req))) {
    return res.status(429).json({ error: 'Terlalu banyak request. Tunggu sebentar lalu coba lagi.' });
  }

  const expectedCode = process.env.VISTARA_ACCESS_CODE;
  const apiKey = process.env.GEMINI_API_KEY;
  if (!expectedCode || !apiKey) {
    return res.status(500).json({ error: 'Server belum dikonfigurasi (VISTARA_ACCESS_CODE / GEMINI_API_KEY)' });
  }

  const givenCode = req.headers['x-vistara-code'];
  if (!givenCode || !safeEqual(givenCode, expectedCode)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { model, body, verify } = req.body || {};

  // Cek access code saja (dipakai saat login)
  if (verify === true) return res.status(200).json({ ok: true });

  if (!model || !ALLOWED_MODELS.has(model)) {
    return res.status(400).json({ error: 'Model tidak diizinkan' });
  }
  if (!body || typeof body !== 'object' || !Array.isArray(body.contents)) {
    return res.status(400).json({ error: 'Body tidak valid' });
  }

  const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  try {
    const upstream = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': apiKey
      },
      body: JSON.stringify(body)
    });

    const text = await upstream.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      data = { error: { message: text.slice(0, 300) } };
    }
    return res.status(upstream.status).json(data);
  } catch (e) {
    return res.status(502).json({ error: e.message });
  }
}