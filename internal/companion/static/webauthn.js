'use strict';

// Shared by the companion's pages: the JSON API, and the passkey ceremonies in
// the shapes the companion's API takes. Binary members travel as base64url in
// options and as standard base64 in the bodies the page sends back.
(function () {
  function b64urlToBytes(s) {
    let b = s.replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    const bin = atob(b);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function bytesToB64(buf) {
    const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  class APIError extends Error {
    constructor(status, code, message) {
      super(message);
      this.status = status;
      this.code = code;
    }
  }

  // api calls the companion. Every change is a POST with a JSON body, which
  // is what the server requires of a request from its own page.
  async function api(method, path, body) {
    const init = { method, credentials: 'same-origin', headers: {}, cache: 'no-store' };
    if (method !== 'GET') {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body || {});
    }
    let resp;
    try {
      resp = await fetch(path, init);
    } catch (_) {
      throw new APIError(0, 'network', 'Keyhole could not be reached. Check your connection.');
    }
    const type = resp.headers.get('Content-Type') || '';
    if (!resp.ok) {
      let code = '';
      let message = 'Keyhole answered ' + resp.status + '.';
      if (type.startsWith('application/json')) {
        try {
          const e = await resp.json();
          code = e.error.code;
          message = e.error.message;
        } catch (_) { /* keep the generic message */ }
      }
      throw new APIError(resp.status, code, message);
    }
    return type.startsWith('application/json') ? resp.json() : resp.text();
  }

  function descriptors(list) {
    return (list || []).map((c) => ({ type: c.type, id: b64urlToBytes(c.id) }));
  }

  // create makes a passkey from the server's creation options and returns
  // the registration the enroll API takes.
  async function create(o) {
    const cred = await navigator.credentials.create({
      publicKey: {
        challenge: b64urlToBytes(o.challenge),
        rp: o.rp,
        user: { id: b64urlToBytes(o.user.id), name: o.user.name, displayName: o.user.displayName },
        pubKeyCredParams: o.pubKeyCredParams,
        authenticatorSelection: o.authenticatorSelection,
        attestation: o.attestation,
        excludeCredentials: descriptors(o.excludeCredentials),
        timeout: o.timeout,
      },
    });
    const r = cred.response;
    if (typeof r.getPublicKey !== 'function' || typeof r.getAuthenticatorData !== 'function') {
      throw new Error('This browser is too old to enroll a Keyhole passkey. Update it and try again.');
    }
    const key = r.getPublicKey();
    if (!key) throw new Error('This browser could not read the new passkey\'s public key.');
    return {
      credential_id: cred.id,
      public_key: bytesToB64(key),
      algorithm: r.getPublicKeyAlgorithm(),
      authenticator_data: bytesToB64(r.getAuthenticatorData()),
      client_data_json: bytesToB64(r.clientDataJSON),
    };
  }

  // assert signs the server's challenge with a passkey and returns the
  // assertion the sign-in and approve APIs take.
  async function assert(o) {
    const cred = await navigator.credentials.get({
      publicKey: {
        challenge: b64urlToBytes(o.challenge),
        rpId: o.rpId,
        allowCredentials: descriptors(o.allowCredentials),
        userVerification: o.userVerification,
        timeout: o.timeout,
      },
    });
    const r = cred.response;
    const out = {
      credential_id: cred.id,
      authenticator_data: bytesToB64(r.authenticatorData),
      client_data_json: bytesToB64(r.clientDataJSON),
      signature: bytesToB64(r.signature),
    };
    if (r.userHandle && r.userHandle.byteLength) out.user_handle = bytesToB64(r.userHandle);
    return out;
  }

  // explain turns a failure into a sentence for the technician.
  function explain(err) {
    switch (err && err.name) {
      case 'NotAllowedError':
        return 'The passkey prompt was cancelled or timed out.';
      case 'InvalidStateError':
        return 'This device already holds a Keyhole passkey for you. Sign in with it instead.';
      case 'SecurityError':
        return 'The browser refused the passkey for this address. Open Keyhole at its usual address.';
      case 'NotSupportedError':
        return 'This device cannot make a passkey Keyhole accepts.';
    }
    return (err && err.message) || 'Something went wrong.';
  }

  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext);
  }

  window.Keyhole = { api, create, assert, explain, supported, APIError };
})();
