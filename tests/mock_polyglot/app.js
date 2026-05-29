const express = require('express');
const app = express();
const router = require('./routes');

// Mount the users router behind the /api prefix
app.use('/api', router);

// Public health check directly on the app (no prefix)
app.get('/health', (req, res) => res.send('ok'));

module.exports = app;
