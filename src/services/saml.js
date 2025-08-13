// src/services/saml.js
const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const zlib = require('zlib');
const { parseStringPromise } = require('xml2js');
const saml = require('samlify');
const { logger } = require('../utils/logger');

// Keep simple for sample—use XSD validator in production
// e.g. saml.setSchemaValidator(require('@authenio/samlify-xsd-schema-validator'));
saml.setSchemaValidator({ validate: () => Promise.resolve() });

// ---------- Config loading ----------
const DEFAULT_CONFIG_PATH = process.env.CONFIG_PATH || path.join(process.cwd(), 'config/config.yml');

function normalizeIdp(raw = {}, where = 'config.yml') {
  const entity_id = raw.entity_id || raw.entityId;
  const sso_url   = raw.sso_url   || raw.ssoUrl;
  const slo_url   = raw.slo_url   || raw.sloUrl; // optional

  const missing = [];
  if (!entity_id) missing.push('idp.entity_id');
  if (!sso_url)   missing.push('idp.sso_url');
  if (missing.length) {
    const got = JSON.stringify(raw);
    throw new Error(`${where}: missing keys ${missing.join(', ')}; got ${got}`);
  }
  return { entity_id, sso_url, slo_url };
}

function loadConfig() {
  if (!fs.existsSync(DEFAULT_CONFIG_PATH)) {
    throw new Error(`Config file not found at ${DEFAULT_CONFIG_PATH}`);
  }
  const raw = fs.readFileSync(DEFAULT_CONFIG_PATH, 'utf8');
  const cfg = yaml.load(raw) || {};
  cfg.idp = normalizeIdp(cfg.idp, DEFAULT_CONFIG_PATH);

  if (!Array.isArray(cfg.service_providers) || cfg.service_providers.length === 0) {
    throw new Error(`${DEFAULT_CONFIG_PATH}: at least one service_providers entry is required`);
  }
  return cfg;
}

const CONFIG = loadConfig();

// ---------- Keys ----------
function readRequiredFile(p, label) {
  if (!fs.existsSync(p)) {
    throw new Error(`Missing ${label} at ${p}`);
  }
  return fs.readFileSync(p, 'utf8');
}
const IDP_PRIVATE_KEY = readRequiredFile(path.join(process.cwd(), 'certs/idp_private.key'), 'IdP private key');
const IDP_PUBLIC_CERT = readRequiredFile(path.join(process.cwd(), 'certs/idp_public.crt'), 'IdP public cert');

// ---------- IdP Entity ----------
const idp = saml.IdentityProvider({
  entityId: CONFIG.idp.entity_id,
  signingCert: IDP_PUBLIC_CERT,
  privateKey: IDP_PRIVATE_KEY,
  wantAuthnRequestsSigned: false,
  singleSignOnService: [
    { Binding: saml.Constants.BindingNamespace.Redirect, Location: CONFIG.idp.sso_url },
    { Binding: saml.Constants.BindingNamespace.Post,     Location: CONFIG.idp.sso_url },
  ],
  singleLogoutService: CONFIG.idp.slo_url
    ? [
        { Binding: saml.Constants.BindingNamespace.Redirect, Location: CONFIG.idp.slo_url },
        { Binding: saml.Constants.BindingNamespace.Post,     Location: CONFIG.idp.slo_url },
      ]
    : undefined,
  responseSigned: true,
  assertionSigned: true,
});

// ---------- SP Registry ----------
function mapBinding(str) {
  return String(str).toLowerCase() === 'post'
    ? saml.Constants.BindingNamespace.Post
    : saml.Constants.BindingNamespace.Redirect;
}

function buildSp(spCfg) {
  const acsServices = (spCfg.acs || []).map(a => ({
    Binding: mapBinding(a.binding || 'post'),
    Location: a.url,
  }));

  const sloServices = (spCfg.slo || []).map(a => ({
    Binding: mapBinding(a.binding || 'redirect'),
    Location: a.url,
  }));

  return saml.ServiceProvider({
    entityId: spCfg.entity_id,
    assertionConsumerService: acsServices,
    singleLogoutService: sloServices, // ok if empty
    wantAssertionsSigned: spCfg.want_assertions_signed !== false,
    wantMessageSigned: !!spCfg.want_message_signed,
    audience: spCfg.audience || spCfg.entity_id,
  });
}

const SP_REGISTRY = new Map(); // key: SP entity_id
for (const spCfg of CONFIG.service_providers) {
  if (!spCfg || !spCfg.entity_id) {
    throw new Error(`${DEFAULT_CONFIG_PATH}: each service_providers entry must include entity_id`);
  }
  const sp = buildSp(spCfg);
  SP_REGISTRY.set(spCfg.entity_id, { key: spCfg.key, cfg: spCfg, sp });
}

function getSpByIssuer(issuer) {
  return SP_REGISTRY.get(issuer);
}

// ---------- Attribute Mapping ----------
function mapAttributesForSp(spKey, profile) {
  const defaults = {
    email: profile.email,
    displayName: profile.displayName,
    givenName: profile.givenName,
    sn: profile.sn,
    groups: profile.groups,
    uid: profile.username,
  };

  const map = (CONFIG.attribute_maps && CONFIG.attribute_maps[spKey]) || null;
  if (!map) return defaults;

  const out = {};
  for (const [local, samlName] of Object.entries(map)) {
    if (local in defaults && defaults[local] != null) {
      out[samlName] = defaults[local];
    }
  }
  return out;
}

// ---------- Issuer Extraction ----------
async function getIssuerFromRequest(req) {
  // Redirect binding (GET): SAMLRequest is DEFLATE-compressed + base64
  if (req.method === 'GET' && req.query.SAMLRequest) {
    try {
      const xml = zlib.inflateRawSync(Buffer.from(req.query.SAMLRequest, 'base64')).toString('utf8');
      const obj = await parseStringPromise(xml);
      return (
        obj?.['samlp:AuthnRequest']?.['saml:Issuer']?.[0] ||
        obj?.AuthnRequest?.Issuer?.[0] ||
        null
      );
    } catch (e) {
      logger.warn(`Failed to parse Redirect SAMLRequest for issuer: ${e.message}`);
      return null;
    }
  }

  // POST binding: base64-encoded XML
  if (req.method === 'POST' && req.body && req.body.SAMLRequest) {
    try {
      const xml = Buffer.from(req.body.SAMLRequest, 'base64').toString('utf8');
      const obj = await parseStringPromise(xml);
      return (
        obj?.['samlp:AuthnRequest']?.['saml:Issuer']?.[0] ||
        obj?.AuthnRequest?.Issuer?.[0] ||
        null
      );
    } catch (e) {
      logger.warn(`Failed to parse POST SAMLRequest for issuer: ${e.message}`);
      return null;
    }
  }

  // Some SPs might send SAMLResponse during SLO; not needed for issuer selection in our login flow.
  return null;
}

module.exports = {
  idp,
  getSpByIssuer,
  mapAttributesForSp,
  getIssuerFromRequest,
  CONFIG, // exported in case you want to introspect elsewhere
};
