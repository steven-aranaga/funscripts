const express = require('express');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Joi = require('joi');
const compression = require('compression');
const app = express();
const PORT = 3800;

// Security middleware
app.use(helmet());
app.use(helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
}));
app.use(compression());
app.use(rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
}));

// Input validation middleware
app.use('/api/get-addresses', (req, res, next) => {
    const schema = Joi.object({
        max: Joi.number().min(0).max(15).default(15)
    });
    
    const { error } = schema.validate(req.query);
    if (error) {
        return res.status(400).json({ error: error.details[0].message });
    }
    next();
});

// Add address validation regex
const BITCOIN_ADDRESS_REGEX = /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/;

app.get('/api/get-addresses', (req, res) => {
    // Add security headers
    res.set({
        'X-Content-Type-Options': 'nosniff',
        'Strict-Transport-Security': 'max-age=63072000; includeSubDomains; preload'
    });
    const filePath = path.join(__dirname, '..', 'backend', 'target_wallets.tsv');
    const maxAmount = parseFloat(req.query.max) || 15.0;

    // Validate maximum amount
    if (maxAmount > 15.0) {
        return res.status(400).json({ error: 'Maximum allowed amount is 15 BTC' });
    }

    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }

        // Filter and process data
        const lines = data.split('\n').slice(1); // Skip header
        const filtered = lines
            .filter(line => {
                if (!line.trim()) return false;
                const [address, balance] = line.split('\t');
                const btcBalance = parseFloat(balance);
                
                // Validate address format and enforce balance rules
                return BITCOIN_ADDRESS_REGEX.test(address) && 
                       btcBalance <= maxAmount && 
                       btcBalance <= 15.0 &&
                       (btcBalance <= 30.0 || req.query.admin === 'true') && // Admin override
                       btcBalance > 0;
            })
            .slice(0, 50); // Limit to 50 results

        res.json({ result: filtered });
    });
});

app.get('/api/get-wallets', (req, res) => {
    const filePath = path.join(__dirname, '..', 'backend', 'active_wallets.txt');

    // Read the file and return specific data
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }
        res.json({ result: data });
    });
});

// Add health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'ok',
        timestamp: Date.now(),
        version: process.env.npm_package_version,
        checks: {
            fileSystem: fs.existsSync('../backend/target_wallets.tsv'),
            recentUpdate: Date.now() - fs.statSync('../backend/target_wallets.tsv').mtimeMs < 300000
        }
    });
});

app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
});
