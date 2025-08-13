// src/services/ldap.js
const { Client } = require('ldapts');

function ldapClient() {
  return new Client({ url: process.env.LDAP_URL });
}

async function authenticateLdap(username, password) {
  const usernameAttr = process.env.LDAP_USERNAME_ATTRIBUTE || 'uid';
  const baseDN = process.env.LDAP_BASE_DN;

  const svc = ldapClient();
  try {
    // 1) Bind with search account
    await svc.bind(process.env.LDAP_BIND_DN, process.env.LDAP_BIND_PASSWORD);

    // 2) Lookup user
    const filter = `(${usernameAttr}=${username})`;
    const { searchEntries } = await svc.search(baseDN, {
      scope: 'sub',
      filter,
      attributes: ['dn', 'cn', 'mail', 'memberOf', usernameAttr, 'displayName', 'givenName', 'sn'],
    });
    if (!searchEntries.length) throw new Error('User not found');

    const user = searchEntries[0];
    const userDN = user.dn;

    // 3) Rebind as the user to verify password
    await svc.unbind();
    const userClient = ldapClient();
    await userClient.bind(userDN, password);
    await userClient.unbind();

    // 4) Normalize attributes
    const groups = Array.isArray(user.memberOf)
      ? user.memberOf
      : (user.memberOf ? [user.memberOf] : []);

    return {
      dn: userDN,
      username: user[usernameAttr] || username,
      email: user.mail,
      displayName: user.displayName || user.cn || `${user.givenName || ''} ${user.sn || ''}`.trim(),
      groups,
      givenName: user.givenName,
      sn: user.sn,
    };
  } finally {
    try { await svc.unbind(); } catch {}
  }
}

module.exports = { authenticateLdap };
