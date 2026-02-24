require('dotenv').config();
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const twilio = require('twilio');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Twilio Configuration
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;

// Check Twilio credentials early
if (!accountSid || !authToken || !twilioPhoneNumber) {
    console.error('Missing Twilio credentials. Please set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, and TWILIO_PHONE_NUMBER.');
    process.exit(1);
}

const client = twilio(accountSid, authToken);

// JWT Secret (used for authenticating WhatsApp send endpoint)
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// In-memory store for verification codes (phone -> { code, expiresAt })
const verificationCodes = new Map();

// Clean expired codes every minute
setInterval(() => {
    const now = Date.now();
    for (const [phone, data] of verificationCodes.entries()) {
        if (data.expiresAt < now) {
            verificationCodes.delete(phone);
        }
    }
}, 60 * 1000);

// ============ WHATSAPP AUTHENTICATION CODE ROUTE ============

// Generate and send a verification code via WhatsApp
app.post('/api/auth/send-code', async (req, res) => {
    try {
        const { phoneNumber } = req.body;

        if (!phoneNumber) {
            return res.status(400).json({ error: 'Phone number is required' });
        }

        // Generate a 6-digit code
        const code = Math.floor(100000 + Math.random() * 900000).toString();

        // Store with expiration (5 minutes)
        const expiresAt = Date.now() + 5 * 60 * 1000;
        verificationCodes.set(phoneNumber, { code, expiresAt });

        // Format phone number for WhatsApp
        const formattedTo = phoneNumber.startsWith('whatsapp:') ? phoneNumber : `whatsapp:${phoneNumber}`;

        // Send the code via Twilio WhatsApp
        const message = await client.messages.create({
            body: `Your verification code is: ${code}`,
            from: `whatsapp:${twilioPhoneNumber}`,
            to: formattedTo
        });

        // ⚠️ In production, remove `code` from the response – never return the actual code.
        res.json({
            success: true,
            message: 'Verification code sent',
            code: code,               // Remove this line in production
            messageSid: message.sid
        });
    } catch (error) {
        console.error('Error sending verification code:', error);
        res.status(500).json({ error: 'Failed to send verification code', details: error.message });
    }
});

// Verify the code (optional – can be used later)
app.post('/api/auth/verify-code', (req, res) => {
    const { phoneNumber, code } = req.body;
    if (!phoneNumber || !code) {
        return res.status(400).json({ error: 'Phone number and code are required' });
    }

    const stored = verificationCodes.get(phoneNumber);
    if (!stored || stored.expiresAt < Date.now()) {
        return res.status(400).json({ error: 'Invalid or expired code' });
    }

    if (stored.code !== code) {
        return res.status(400).json({ error: 'Incorrect code' });
    }

    // Code is valid – delete it so it can't be reused
    verificationCodes.delete(phoneNumber);

    // Here you could issue a temporary JWT or mark the phone as verified
    res.json({ success: true, message: 'Code verified' });
});

// ============ WHATSAPP MESSAGE ROUTES ============

// Send WhatsApp message (authenticated)
app.post('/api/whatsapp/send', authenticateToken, async (req, res) => {
    try {
        const { to, body } = req.body;

        if (!to || !body) {
            return res.status(400).json({ error: 'Phone number and message body are required' });
        }

        const formattedTo = to.startsWith('whatsapp:') ? to : `whatsapp:${to}`;

        const message = await client.messages.create({
            body: body,
            from: `whatsapp:${twilioPhoneNumber}`,
            to: formattedTo
        });

        res.json({
            success: true,
            messageSid: message.sid,
            status: message.status
        });
    } catch (error) {
        console.error('Twilio error:', error.message);
        res.status(500).json({ error: 'Failed to send WhatsApp message', details: error.message });
    }
});

// Send WhatsApp message (public - for testing)
app.post('/api/whatsapp/send-message', async (req, res) => {
    try {
        const { to, body } = req.body;

        if (!to || !body) {
            return res.status(400).json({ error: 'Phone number and message body are required' });
        }

        const formattedTo = to.startsWith('whatsapp:') ? to : `whatsapp:${to}`;

        const message = await client.messages.create({
            body: body,
            from: `whatsapp:${twilioPhoneNumber}`,
            to: formattedTo
        });

        res.json({
            success: true,
            messageSid: message.sid,
            status: message.status
        });
    } catch (error) {
        console.error('Twilio error:', error.message);
        res.status(500).json({ error: 'Failed to send WhatsApp message', details: error.message });
    }
});

// ============ MIDDLEWARE ============

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
}

// ============ HEALTH CHECK ============

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ START SERVER ============

app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

module.exports = app;