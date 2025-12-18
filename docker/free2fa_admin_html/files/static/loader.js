// Load control.js only if the browser is supported
(function () {
  function onReady(fn) {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', fn, false);
    } else {
      fn();
    }
  }

  onReady(function () {
    if (window.__APP_FEATURES_OK__) {         // NOSONAR (legacy ES5 bootstrap file)
      document.body.appendChild((function (el) {
        el.src = './static/control.js';
        el.async = false; // predictable order
        return el;
      })(document.createElement('script')));
    } else {
      if (window.console && console.warn) {   // NOSONAR (legacy ES5 bootstrap file)
        console.warn('Unsupported browser:', window.__APP_FEATURES_MISSING__);
      }
    }
  });
})();
