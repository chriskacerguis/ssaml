const express = require('express');
const router = express.Router();
const { idp } = require('../services/saml');
router.get('/', (_req, res) => res.type('application/xml').send(idp.getMetadata()));
module.exports = router;
