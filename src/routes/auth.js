const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { authenticateLdap } = require('../services/ldap');
const { idp, getSpByIssuer, mapAttributesForSp } = require('../services/saml');
const saml = require('samlify');

router.get('/', (req, res) => {
  const relayState = req.query.RelayState || req.session.RelayState || '';
  res.render('login', { relayState });
});

router.post('/', async (req, res, next) => {
  const { username, password, RelayState } = req.body;

  try {
    const profile = await authenticateLdap(username, password);
    req.session.user = profile;

    // If we have a pending SAML request, complete it
    if (req.session.PendingRequest) {
      const { binding, issuer } = req.session.PendingRequest;

      const spEntry = getSpByIssuer(issuer);
      if (!spEntry) return res.status(400).send(`Unknown SP issuer: ${issuer}`);

      const { key, cfg, sp } = spEntry;

      // Enforce allowed_groups silently (do not disclose authorization status)
      if (cfg.allowed_groups && Array.isArray(cfg.allowed_groups) && cfg.allowed_groups.length > 0) {
        const inAllowedGroup = (profile.groups || []).some(g => cfg.allowed_groups.includes(g));
        if (!inAllowedGroup) {
          // Fail like invalid credentials
          return res.status(401).send('Invalid credentials');
        }
      }

      const now = new Date();
      const attributes = mapAttributesForSp(key, profile);

      const loginResp = await idp.createLoginResponse(sp, binding, {
        relayState: RelayState || req.session.RelayState || '',
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

    // No pending request: simple success page
    return res.send(`Logged in as ${profile.displayName || profile.username}.`);
  } catch (err) {
    err.status = 401;
    next(err);
  }
});

module.exports = router;
