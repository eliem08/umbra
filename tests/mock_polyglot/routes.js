const express = require('express');
const router = express.Router();
const requireAuth = require('./middleware/auth');

// Authorized via inline middleware
router.get('/profile', requireAuth, (req, res) => {
  res.json({ ok: true });
});

// Public, no auth middleware
router.post('/public-comment', (req, res) => {
  res.json({ created: true });
});

// Shadow-ish admin route, no auth
router.get('/admin/:section', (req, res) => {
  res.json({ section: req.params.section });
});

module.exports = router;
