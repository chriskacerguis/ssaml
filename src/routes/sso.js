const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { idp, getIssuerFromRequest, getSpByIssuer, mapAttributesForSp } = require('../services/saml');
const saml = require('samlify');

router.all('/', async (req, res, next) => {
  try {
    const issuer = await getIssuerFromRequest(req);
    if (!issuer) return res.status(400).send('Missing or invalid SAMLRequest (no Issuer)');

    const spEntry = getSpByIssuer(issuer);
    if (!spEntry) return res.status(400).send(`Unknown SP issuer: ${issuer}`);

    const { key, cfg, sp } = spEntry;
    const binding = (req.method === 'GET') ? 'redirect' : 'post';

    // If already authenticated, issue response
    if (req.session.user) {
      const profile = req.session.user;

      // Enforce allowed_groups silently by forcing a fresh login if not allowed
      if (cfg.allowed_groups && Array.isArray(cfg.allowed_groups) && cfg.allowed_groups.length > 0) {
        const inAllowedGroup = (profile.groups || []).some(g => cfg.allowed_groups.includes(g));
        if (!inAllowedGroup) {
          req.session.destroy(() => {});
          return res.redirect('/login');
        }
      }

      const now = new Date();
      const attributes = mapAttributesForSp(key, profile);
      const relayState = req.body.RelayState || req.query.RelayState || '';

      const loginResp = await idp.createLoginResponse(sp, binding, {
        relayState,
        extract: {
          nameID: profile.email || profile.username,
          nameIDFormat: cfg.nameid_format || saml.Constants.NameIDFormat.EmailAddress,
          sessionIndex: uuidv4(),
          authnContextClassRef: saml.Constants.AuthnContextClassRef.PasswordProtectedTransport,
          audience: cfg.audience || cfg.entity_id,
          attributes,
          subjectConfirmationData: {
            Recipient: (cfg.acs && cfg.acs[0]?.url) || '',
            NotOnOrAfter: new Date(now.getTime() + 5 * 60 * 1000),
          },
          conditions: {
            AudienceRestriction: [{ Audience: cfg.audience || cfg.entity_id }],
            NotBefore: new Date(now.getTime() - 2 * 60 * 1000),
            NotOnOrAfter: new Date(now.getTime() + 5 * 60 * 1000),
          },
        },
      });

      return res.type('html').send(loginResp.context);
    }

    // Not authenticated yet: stash context and go to login
    req.session.PendingRequest = { binding, issuer };
    req.session.RelayState = req.body.RelayState || req.query.RelayState || '';
    return res.redirect(`/login?RelayState=${encodeURIComponent(req.session.RelayState)}`);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
