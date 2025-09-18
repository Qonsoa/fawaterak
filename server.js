// server.js
// Production-ready Express server for Fawaterak IFrame integration
// Node >= 14
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const getRawBody = require('raw-body');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

/**
 * Required env variables (see .env.example)
 * FAWATERAK_VENDOR_KEY      -> secret vendor key (server-only, used for HMAC & Bearer if creating invoice server-side)
 * FAWATERAK_PROVIDER_KEY    -> provider key (from dashboard)
 * FAWATERAK_DOMAIN          -> domain you registered in dashboard e.g. https://captain-gym.com
 * FAWATERAK_USE_STAGING     -> "1" to use staging createInvoiceLink endpoint; otherwise production endpoint assumed
 * FAWATERAK_CREATE_ON_SERVER -> "1" to call createInvoiceLink on server; otherwise plugin will render iframe directly
 * FAWATERAK_WEBHOOK_SECRET  -> optional: shared secret to verify webhook HMAC signature if configured
 */

if (!process.env.FAWATERAK_VENDOR_KEY || !process.env.FAWATERAK_PROVIDER_KEY || !process.env.FAWATERAK_DOMAIN) {
  console.warn('⚠️ Please set FAWATERAK_VENDOR_KEY, FAWATERAK_PROVIDER_KEY and FAWATERAK_DOMAIN in your environment.');
}

/* -------------- Middlewares -------------- */
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*' // set to your frontend origin in production
}));
app.use(express.json({ limit: '100kb' })); // parse JSON body for normal routes
app.use(express.static('public'));

// Basic rate limiting for security
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

/* -------------- Helpers -------------- */

/**
 * Generate hashKey for plugin iframe:
 * hash = HMAC_SHA256("Domain=your_domain&ProviderKey=FAWATERAK_PROVIDER_KEY", FAWATERAK_VENDOR_KEY)
 */
function generateHashKey(domain = process.env.FAWATERAK_DOMAIN) {
  const providerKey = process.env.FAWATERAK_PROVIDER_KEY;
  const vendorKey = process.env.FAWATERAK_VENDOR_KEY;
  const queryParam = `Domain=${domain}&ProviderKey=${providerKey}`;
  const hmac = crypto.createHmac('sha256', vendorKey);
  hmac.update(queryParam);
  return hmac.digest('hex');
}

/* -------------- Routes -------------- */

/**
 * GET /api/fawaterak/hashkey
 * Returns a freshly generated hashKey for the registered domain.
 */
app.get('/api/fawaterak/hashkey', (req, res) => {
  try {
    const domain = process.env.FAWATERAK_DOMAIN;
    const hashKey = generateHashKey(domain);
    return res.json({ ok: true, hashKey });
  } catch (err) {
    console.error('hashkey error:', err);
    return res.status(500).json({ ok: false, message: 'Failed to generate hashKey' });
  }
});

/**
 * POST /api/fawaterak/create-invoice
 * Body: { cartTotal, currency, customer, cartItems, payLoad, redirectionUrls }
 * Returns: { ok, hashKey, requestBody, apiResult? }
 *
 * By default (FAWATERAK_CREATE_ON_SERVER !== '1') this endpoint returns hashKey + requestBody so frontend plugin renders iframe.
 * If FAWATERAK_CREATE_ON_SERVER === '1', server will call createInvoiceLink endpoint (staging or production) and return apiResult.
 */
app.post('/api/fawaterak/create-invoice', async (req, res) => {
  try {
    // Basic validation/sanitization (keep it simple; expand as needed)
    const body = req.body || {};
    const cartTotal = body.cartTotal || 0;
    if (Number(cartTotal) <= 0) {
      return res.status(400).json({ ok: false, message: 'cartTotal must be > 0' });
    }

    const requestBody = {
      cartTotal: String(cartTotal),
      currency: body.currency || 'EGP',
      customer: {
        first_name: body.customer?.first_name || '',
        last_name: body.customer?.last_name || '',
        email: body.customer?.email || '',
        phone: body.customer?.phone || '',
        address: body.customer?.address || ''
      },
      cartItems: Array.isArray(body.cartItems) ? body.cartItems : [],
      payLoad: body.payLoad || {},
      redirectionUrls: body.redirectionUrls || {}
    };

    // generate hashKey (server-only)
    const domain = process.env.FAWATERAK_DOMAIN;
    const hashKey = generateHashKey(domain);

    let apiResult = null;
    if (process.env.FAWATERAK_CREATE_ON_SERVER === '1') {
      // call createInvoiceLink endpoint (Docs: staging URL for testing)
      const useStaging = process.env.FAWATERAK_USE_STAGING === '1';
      const createInvoiceUrl = useStaging
        ? 'https://staging.fawaterk.com/api/v2/createInvoiceLink'
        : 'https://fawaterk.com/api/v2/createInvoiceLink'; // confirm with your dashboard if different

      // Build payload per docs: many docs expect the request body exactly as JSON
      // The endpoint also expects Authorization: Bearer {API_KEY}
      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.FAWATERAK_VENDOR_KEY}`
      };

      // Combine optional provider key if docs require it in body; adjust if your docs differ
      const payloadToApi = {
        ...requestBody,
        ProviderKey: process.env.FAWATERAK_PROVIDER_KEY,
        HashKey: hashKey
      };

      const axiosRes = await axios.post(createInvoiceUrl, payloadToApi, { headers, timeout: 10000 });
      apiResult = axiosRes.data; // expected: { status: 'success', data: { url, invoiceKey, invoiceId } } (check your docs)
    }

    return res.json({ ok: true, hashKey, requestBody, apiResult });
  } catch (err) {
    console.error('create-invoice error:', err.response ? err.response.data : err.message);
    return res.status(500).json({ ok: false, message: 'Failed to create invoice', error: err.message });
  }
});

/**
 * POST /api/fawaterak/webhook_json
 * This endpoint receives webhook notifications from Fawaterak.
 * It reads raw body to allow signature verification if FAWATERAK_WEBHOOK_SECRET is set.
 */
app.post('/api/fawaterak/webhook_json', async (req, res) => {
  try {
    // Read raw body for signature verification
    const raw = await getRawBody(req);
    const payloadRaw = raw.toString('utf8');

    let payload;
    try { payload = JSON.parse(payloadRaw || '{}'); } catch (e) {
      console.warn('Webhook payload is not valid JSON');
      payload = {};
    }

    // Optional signature verification
    const webhookSecret = process.env.FAWATERAK_WEBHOOK_SECRET;
    const signatureHeader = req.headers['x-fawaterak-signature'] || req.headers['x-signature'] || null;

    if (webhookSecret && signatureHeader) {
      const computed = crypto.createHmac('sha256', webhookSecret).update(payloadRaw).digest('hex');
      if (computed !== signatureHeader) {
        console.warn('Webhook signature mismatch');
        return res.status(401).send('invalid signature');
      }
    }

    // Process payload (fields may vary; adapt to the exact structure in your dashboard/docs)
    console.log('Fawaterak webhook received:', JSON.stringify(payload, null, 2));

    const status = payload.invoiceStatus || payload.status || payload.invoice_status || (payload.data && payload.data.status) || null;
    const invoiceId = payload.invoiceId || payload.invoice_id || (payload.data && payload.data.invoiceId) || null;

    if (status && String(status).toLowerCase() === 'paid') {
      // TODO: update your DB: mark order as paid based on invoiceId or payload.payLoad.userId
      console.log(`Invoice ${invoiceId} marked as PAID. Update your system accordingly.`);
      // Example:
      // await Orders.markPaid(invoiceId, payload);
      // send email / whatsapp receipt to customer
    }

    // Always reply quickly
    return res.status(200).send('OK');
  } catch (err) {
    console.error('webhook processing error:', err);
    return res.status(500).send('error');
  }
});

/* Fallback */
app.use((req, res) => {
  res.status(404).send('Not found');
});

/* Start server */
app.listen(PORT, () => {
  console.log(`Fawaterak demo server listening on port ${PORT}`);
});
