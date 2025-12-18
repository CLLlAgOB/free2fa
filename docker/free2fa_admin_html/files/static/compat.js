// ES5-compatible feature detection. No let/const/arrows.
(function () {
  function has(path) {
    var parts = path.split('.'), obj = window, i;  // NOSONAR (legacy ES5 bootstrap file)
    for (i = 0; i < parts.length; i++) {
      obj = (obj && obj[parts[i]]) ? obj[parts[i]] : null;
    }
    return !!obj;
  }

  var missing = [];  // NOSONAR (legacy ES5 bootstrap file)
  if (!('fetch' in window)) missing.push('Fetch API'); // NOSONAR (legacy ES5 bootstrap file)
  if (!('Promise' in window)) missing.push('Promise'); // NOSONAR (legacy ES5 bootstrap file)
  if (!('AbortController' in window)) missing.push('AbortController'); // NOSONAR (legacy ES5 bootstrap file)
  if (!('URLSearchParams' in window)) missing.push('URLSearchParams'); // NOSONAR (legacy ES5 bootstrap file)
  if (!('TextEncoder' in window)) missing.push('TextEncoder'); // NOSONAR (legacy ES5 bootstrap file)
  if (!has('crypto.subtle')) missing.push('WebCrypto (crypto.subtle)'); // NOSONAR (legacy ES5 bootstrap file)

  // безопасная проверка Element.replaceChildren (старые браузеры)
  var elProto = window.Element ? window.Element.prototype : null; // NOSONAR (legacy ES5 bootstrap file)
  if (!(elProto && 'replaceChildren' in elProto)) {
    missing.push('Element.replaceChildren'); // NOSONAR (legacy ES5 bootstrap file)
  }

  if (!('sessionStorage' in window)) missing.push('sessionStorage'); // NOSONAR (legacy ES5 bootstrap file)

  var supported = (missing.length === 0);     // NOSONAR (legacy ES5 bootstrap file)
  window.__APP_FEATURES_OK__ = supported;     // NOSONAR (legacy ES5 bootstrap file)
  window.__APP_FEATURES_MISSING__ = missing;  // NOSONAR (legacy ES5 bootstrap file)

  if (!supported) {
    var show = function () {  // NOSONAR (legacy ES5 bootstrap file)
      try {
        var banner = document.createElement('div');  // NOSONAR (legacy ES5 bootstrap file)
        banner.className = 'unsupported-banner';
        banner.innerHTML =                           // NOSONAR (legacy ES5 bootstrap file)
          '<strong>Your browser is outdated.</strong> Your browser is outdated: ' +
          missing.join(', ') +
          '. Update your browser (Chrome/Edge/Firefox/Safari) or use another one. ';

        document.body.insertBefore(banner, document.body.firstChild);

        // Hide working sections so as not to confuse the user
        var hide = function (id) {                // NOSONAR (legacy ES5 bootstrap file)
          var el = document.getElementById(id);   // NOSONAR (legacy ES5 bootstrap file)
          if (el) { el.style.display = 'none'; }  // NOSONAR (legacy ES5 bootstrap file)
        };                                        // NOSONAR (legacy ES5 bootstrap file)
        hide('loginSection');
        hide('mainContent');
        hide('changePasswordSection');
      } catch (e) { // handle properly: log + fail fast
        try {
          if (window.console && window.console.error) {                               // NOSONAR (legacy ES5 bootstrap file)
            window.console.error('ES5 bootstrap failed in compat check:', e);         // NOSONAR (legacy ES5 bootstrap file)
          }
          window.__APP_FEATURES_ERROR__ = (e && e.message) ? e.message : String(e);   // NOSONAR (legacy ES5 bootstrap file)
        } catch (ignore) { }
        try {
          alert('Your browser is too old for this page. Please update it.');          // NOSONAR (legacy ES5 bootstrap file)
        } catch (ignore2) { }
        throw e;
      }
    };

    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', show);
    } else {
      show();
    }
  }
})();
