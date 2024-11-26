const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = 3800;

app.get('/api/get-addresses', (req, res) => {
    const filePath = path.join(__dirname, '..', 'backend', 'target_wallets.tsv');

    // Read the file and return specific data
    fs.readFile(filePath, 'utf8', (err, data) => {
        if (err) {
            console.error(err);
            return res.status(500).send('Internal Server Error');
        }
        res.json({ result: data });
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

app.listen(PORT, '127.0.0.1', () => {
    console.log(`Server running on http://127.0.0.1:${PORT}`);
});