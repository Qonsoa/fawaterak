// server.js
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const path = require('path');

const app = express();
// إعداد trust proxy ليعمل بشكل صحيح مع Railway
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;

/* -------------- Middlewares -------------- */
app.use(helmet({
  contentSecurityPolicy: false // تعطيل CSP مؤقتاً للتحقق من المشاكل
}));

app.use(cors({
  origin: process.env.ALLOWED_ORIGIN || '*'
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// إعداد rate limiting بشكل صحيح
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  message: 'Too many requests from this IP',
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip; // استخدام IP العميل الحقيقي
  }
});

app.use(limiter);

/* -------------- Helpers -------------- */
function generateHashKey(domain = process.env.FAWATERAK_DOMAIN) {
  const providerKey = process.env.FAWATERAK_PROVIDER_KEY || '';
  const vendorKey = process.env.FAWATERAK_VENDOR_KEY || '';
  const queryParam = `Domain=${domain}&ProviderKey=${providerKey}`;
  const hmac = crypto.createHmac('sha256', vendorKey);
  hmac.update(queryParam);
  return hmac.digest('hex');
}

/* -------------- API Routes -------------- */

// GET /api/fawaterak/hashkey
app.get('/api/fawaterak/hashkey', (req, res) => {
  try {
    const domain = process.env.FAWATERAK_DOMAIN || `${req.protocol}://${req.get('host')}`;
    const hashKey = generateHashKey(domain);
    return res.json({ ok: true, hashKey });
  } catch (err) {
    console.error('hashkey error:', err);
    return res.status(500).json({ ok: false, message: 'Failed to generate hashKey' });
  }
});

// POST /api/fawaterak/create-invoice
app.post('/api/fawaterak/create-invoice', async (req, res) => {
  try {
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

    const domain = process.env.FAWATERAK_DOMAIN || `${req.protocol}://${req.get('host')}`;
    const hashKey = generateHashKey(domain);

    let apiResult = null;
    if (process.env.FAWATERAK_CREATE_ON_SERVER === '1') {
      const useStaging = process.env.FAWATERAK_USE_STAGING === '1';
      const createInvoiceUrl = useStaging
        ? 'https://staging.fawaterk.com/api/v2/createInvoiceLink'
        : 'https://fawaterk.com/api/v2/createInvoiceLink';

      const headers = {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.FAWATERAK_VENDOR_KEY || ''}`
      };

      const payloadToApi = {
        ...requestBody,
        ProviderKey: process.env.FAWATERAK_PROVIDER_KEY,
        HashKey: hashKey
      };

      try {
        const axiosRes = await axios.post(createInvoiceUrl, payloadToApi, { headers, timeout: 10000 });
        apiResult = axiosRes.data;
      } catch (axiosError) {
        console.error('Fawaterak API error:', axiosError.response?.data || axiosError.message);
        return res.status(502).json({ 
          ok: false, 
          message: 'Failed to create invoice with Fawaterak', 
          error: axiosError.message 
        });
      }
    }

    return res.json({ ok: true, hashKey, requestBody, apiResult });
  } catch (err) {
    console.error('create-invoice error:', err.message);
    return res.status(500).json({ 
      ok: false, 
      message: 'Failed to create invoice', 
      error: err.message 
    });
  }
});

// POST /api/fawaterak/webhook_json
app.post('/api/fawaterak/webhook_json', express.raw({ type: 'application/json' }), (req, res) => {
  try {
    const payloadRaw = req.body.toString('utf8');
    let payload;
    
    try { 
      payload = JSON.parse(payloadRaw || '{}'); 
    } catch (e) { 
      console.warn('Webhook payload is not valid JSON');
      payload = {}; 
    }

    const webhookSecret = process.env.FAWATERAK_WEBHOOK_SECRET;
    const signatureHeader = req.headers['x-fawaterak-signature'] || req.headers['x-signature'] || null;

    if (webhookSecret && signatureHeader) {
      const computed = crypto.createHmac('sha256', webhookSecret).update(payloadRaw).digest('hex');
      if (computed !== signatureHeader) {
        console.warn('Webhook signature mismatch');
        return res.status(401).send('invalid signature');
      }
    }

    console.log('Fawaterak webhook received:', JSON.stringify(payload, null, 2));

    const status = payload.invoiceStatus || payload.status || payload.invoice_status || (payload.data && payload.data.status) || null;
    const invoiceId = payload.invoiceId || payload.invoice_id || (payload.data && payload.data.invoiceId) || null;

    if (status && String(status).toLowerCase() === 'paid') {
      console.log(`Invoice ${invoiceId} marked as PAID. Update your system accordingly.`);
      // TODO: update DB, notify user, etc.
    }

    return res.status(200).send('OK');
  } catch (err) {
    console.error('webhook processing error:', err);
    return res.status(500).send('error');
  }
});

// Route for root - serve index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Fallback for non-handled routes
app.use((req, res) => {
  res.status(404).send('Not found');
});

// Start server
app.listen(PORT, () => {
  console.log(`Fawaterak server listening on port ${PORT}`);
  console.log(`Environment: ${process.env.ENV_TYPE || 'development'}`);
});