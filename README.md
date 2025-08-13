# ssaml
Simple SAML2 front-end built to work with LLDAP.

## Quickstart

```bash
cp .env.example .env
# Generate dev certs (self-signed)
openssl req -x509 -newkey rsa:2048 -keyout certs/idp_private.key -out certs/idp_public.crt -nodes -days 365 -subj "/CN=Local SAML IdP"

npm install
npm start
# open http://localhost:3000/metadata
```