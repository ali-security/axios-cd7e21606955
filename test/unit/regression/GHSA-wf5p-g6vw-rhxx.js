// https://github.com/advisories/GHSA-wf5p-g6vw-rhxx (CVE-2023-45857)
// The XSRF-TOKEN cookie must not be sent to third-party hosts just because `withCredentials` is enabled;
// only the explicit `withXSRFToken` opt-in may send it cross-origin.
//
// test/specs/xsrf.spec.js covers lib/ in real browsers. This suite runs the published browser CommonJS
// bundle (what `require('axios')` resolves to in browser bundlers) against a minimal browser environment.

import assert from 'assert';
import fs from 'fs';
import vm from 'vm';

const BUNDLE_URL = new URL('../../../dist/browser/axios.cjs', import.meta.url);
const ORIGIN = 'http://localhost:8080';
const TOKEN = '12345';

function loadBrowserBundle(cookie) {
  const requests = [];

  function XMLHttpRequest() {
    this.requestHeaders = {};
    this.readyState = 0;
    this.status = 0;
    this.statusText = '';
    this.responseText = '';
    this.response = '';
    this.onloadend = null;
    requests.push(this);
  }

  XMLHttpRequest.prototype.open = function open(method, url) {
    this.method = method;
    this.url = url;
  };

  XMLHttpRequest.prototype.setRequestHeader = function setRequestHeader(name, value) {
    this.requestHeaders[name] = value;
  };

  XMLHttpRequest.prototype.getAllResponseHeaders = function getAllResponseHeaders() {
    return '';
  };

  XMLHttpRequest.prototype.addEventListener = function addEventListener() {};

  XMLHttpRequest.prototype.abort = function abort() {};

  XMLHttpRequest.prototype.send = function send() {
    const request = this;
    request.readyState = 4;
    request.status = 200;
    request.statusText = 'OK';
    setTimeout(function () {
      request.onloadend && request.onloadend();
    });
  };

  const document = {
    cookie,
    createElement() {
      const node = {
        setAttribute(name, value) {
          const url = new URL(value, ORIGIN + '/');
          node.href = url.href;
          node.protocol = url.protocol;
          node.host = url.host;
          node.search = url.search;
          node.hash = url.hash;
          node.hostname = url.hostname;
          node.port = url.port;
          node.pathname = url.pathname;
        }
      };
      return node;
    }
  };

  const module = {exports: {}};

  vm.runInNewContext(fs.readFileSync(BUNDLE_URL, 'utf8'), {
    module,
    exports: module.exports,
    window: {location: {href: ORIGIN + '/'}},
    document,
    navigator: {userAgent: 'node', product: 'Gecko'},
    XMLHttpRequest,
    setTimeout,
    clearTimeout
  }, {filename: BUNDLE_URL.pathname});

  return {axios: module.exports, requests};
}

describe('Cross-site Request Forgery (CVE-2023-45857) - dist/browser/axios.cjs', function () {
  let axios;
  let requests;
  let headerName;

  beforeEach(function () {
    ({axios, requests} = loadBrowserBundle('XSRF-TOKEN=' + TOKEN));
    headerName = axios.defaults.xsrfHeaderName;
  });

  async function sentHeader(url, config) {
    await axios(url, config);
    assert.strictEqual(requests.length, 1);
    return requests[0].requestHeaders[headerName];
  }

  it('should set xsrf header for the same origin', async function () {
    assert.strictEqual(await sentHeader('/foo'), TOKEN);
  });

  it('should not set xsrf header for cross origin', async function () {
    assert.strictEqual(await sentHeader('http://evil.example.com/'), undefined);
  });

  it('should not set xsrf header for cross origin when using withCredentials', async function () {
    assert.strictEqual(await sentHeader('http://evil.example.com/', {withCredentials: true}), undefined);
    assert.strictEqual(requests[0].withCredentials, true);
  });

  it('should not set xsrf header for cross origin when the function resolver returns false', async function () {
    assert.strictEqual(await sentHeader('http://evil.example.com/', {
      withCredentials: true,
      withXSRFToken: () => false
    }), undefined);
  });

  it('should not set xsrf header for cross origin when withXSRFToken is a truthy non-boolean', async function () {
    assert.strictEqual(await sentHeader('http://evil.example.com/', {
      withCredentials: true,
      withXSRFToken: 'false'
    }), undefined);
  });

  it('should not set xsrf header for the same origin when withXSRFToken = false', async function () {
    assert.strictEqual(await sentHeader('/foo', {withXSRFToken: false}), undefined);
  });

  it('should set xsrf header for cross origin when withXSRFToken = true', async function () {
    assert.strictEqual(await sentHeader('http://example.com/', {withXSRFToken: true}), TOKEN);
  });
});
