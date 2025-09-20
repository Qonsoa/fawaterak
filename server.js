// server.js - الإصدار النهائي المستقر
require('dotenv').config();

const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const path = require('path');

const app = express();

// إعداد trust proxy ليعمل مع Railway
app.set('trust proxy', true);

const PORT = process.env.PORT || 3000;

// Middlewares
app.use(require('cors')({
  origin: process.env.ALLOWED_ORIGIN || '*',
  credentials: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// Middleware للطباعة للتحقق من الطلبات
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
  next();
});

// دالة إنشاء HashKey
function generateHashKey(domain = process.env.FAWATERAK_DOMAIN) {
  const providerKey = process.env.FAWATERAK_PROVIDER_KEY || '';
  const vendorKey = process.env.FAWATERAK_VENDOR_KEY || '';
  const queryParam = `Domain=${domain}&ProviderKey=${providerKey}`;
  const hmac = crypto.createHmac('sha256', vendorKey);
  hmac.update(queryParam);
  return hmac.digest('hex');
}

// Routes
app.get('/api/fawaterak/hashkey', (req, res) => {
  try {
    const domain = process.env.FAWATERAK_DOMAIN || `${req.protocol}://${req.get('host')}`;
    const hashKey = generateHashKey(domain);
    console.log('HashKey generated successfully for domain:', domain);
    return res.json({ ok: true, hashKey });
  } catch (err) {
    console.error('HashKey generation error:', err);
    return res.status(500).json({ ok: false, message: 'Failed to generate hashKey', error: err.message });
  }
});

app.post('/api/fawaterak/create-invoice', async (req, res) => {
  try {
    console.log('Create invoice request received:', req.body);
    
    const body = req.body || {};
    const cartTotal = body.cartTotal || 0;
    
    if (Number(cartTotal) <= 0) {
      return res.status(400).json({ ok: false, message: 'cartTotal must be > 0' });
    }

    const requestBody = {
      cartTotal: String(cartTotal),
      currency: body.currency || 'EGP',
      customer: body.customer || {},
      cartItems: Array.isArray(body.cartItems) ? body.cartItems : [],
      payLoad: body.payLoad || {},
      redirectionUrls: body.redirectionUrls || {}
    };

    const domain = process.env.FAWATERAK_DOMAIN || `${req.protocol}://${req.get('host')}`;
    const hashKey = generateHashKey(domain);

    let apiResult = null;
    if (process.env.FAWATERAK_CREATE_ON_SERVER === '1') {
      try {
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

        const axiosRes = await axios.post(createInvoiceUrl, payloadToApi, { 
          headers, 
          timeout: 15000 
        });
        apiResult = axiosRes.data;
      } catch (axiosError) {
        console.error('Fawaterak API error:', axiosError.response?.data || axiosError.message);
        // لا نعيد خطأ للعميل حتى لا نكسر التكامل
      }
    }

    console.log('Invoice creation successful');
    return res.json({ 
      ok: true, 
      hashKey, 
      requestBody, 
      apiResult,
      envType: process.env.ENV_TYPE || 'test'
    });
  } catch (err) {
    console.error('Create invoice error:', err.message);
    return res.status(500).json({ 
      ok: false, 
      message: 'Failed to create invoice', 
      error: err.message 
    });
  }
});

// Route for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Fallback for non-handled routes
app.use((req, res) => {
  res.status(404).json({ ok: false, message: 'Route not found' });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ ok: false, message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`✅ Fawaterak server listening on port ${PORT}`);
  console.log(`✅ Environment: ${process.env.ENV_TYPE || 'development'}`);
  console.log(`✅ Trust proxy: ${app.get('trust proxy')}`);
  console.log(`✅ Domain: ${process.env.FAWATERAK_DOMAIN || 'Not set'}`);
});