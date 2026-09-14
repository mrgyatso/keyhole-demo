'use strict';

// Enrolling a passkey from a one-time link. The link's secret arrives in the
// fragment, which the browser never sends to a server. The page takes it,
// drops it from the address bar and history at once, and sends it only in the
// body of the two enroll requests.
(function () {
  const K = window.Keyhole;
  const $ = (id) => document.getElementById(id);
  const token = decodeURIComponent(location.hash.slice(1));
  if (location.hash) history.replaceState(null, '', location.pathname);

  const button = $('enroll-btn');
  const message = $('enroll-msg');
  const say = (text) => { message.textContent = text; };

  if (!token.startsWith('khp_')) {
    button.disabled = true;
    say('This page needs the one-time enrollment link your administrator sent you. Open that link again, exactly as it was sent.');
    return;
  }
  if (!K.supported()) {
    button.disabled = true;
    say('This browser cannot use passkeys here. Open the link in an up-to-date Safari, Chrome, Edge or Firefox.');
    return;
  }
  $('name').value = guessName();

  button.addEventListener('click', async () => {
    button.disabled = true;
    say('');
    try {
      const begin = await K.api('POST', '/api/enroll/begin', { token });
      const reg = await K.create(begin.options);
      reg.token = token;
      reg.name = $('name').value.trim();
      const done = await K.api('POST', '/api/enroll/finish', reg);
      $('enrolled-text').textContent = 'The passkey "' + done.passkey + '" is enrolled for ' + done.technician +
        ', and you are signed in. The enrollment link no longer works.';
      $('enroll').hidden = true;
      $('enrolled').hidden = false;
    } catch (err) {
      say(K.explain(err));
      button.disabled = false;
    }
  });

  function guessName() {
    const ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua)) return 'iPad';
    if (/Android/.test(ua)) return 'Android phone';
    if (/Macintosh/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows PC';
    return 'Passkey';
  }
})();
