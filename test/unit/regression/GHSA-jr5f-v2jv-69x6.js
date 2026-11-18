// https://github.com/axios/axios/security/advisories/GHSA-jr5f-v2jv-69x6 (CVE-2025-27152)
// When a baseURL is configured, an absolute request URL must not be able to redirect the request (and the
// credentials attached to it) to another host once `allowAbsoluteUrls: false` is set.

import axios from '../../../index.js';
import http from 'http';
import assert from 'assert';
import fs from 'fs';
import vm from 'vm';
import {createRequire} from 'module';

const require = createRequire(import.meta.url);

const GOOD_PORT = 4676;
const BAD_PORT = 4677;
const GOOD_BASE_URL = 'http://localhost:' + String(GOOD_PORT);
const BAD_URL = 'http://localhost:' + String(BAD_PORT) + '/steal';

const AUTH = {username: 'user', password: 'secret'};

describe('Server-Side Request Forgery via absolute URL (CVE-2025-27152)', function () {
  let goodServer, badServer;
  let goodServerRequests, badServerRequests;

  beforeEach(function (done) {
    goodServerRequests = [];
    badServerRequests = [];

    goodServer = http.createServer(function (req, res) {
      goodServerRequests.push({url: req.url, authorization: req.headers.authorization});
      res.end('good');
    }).listen(GOOD_PORT, function () {
      badServer = http.createServer(function (req, res) {
        badServerRequests.push({url: req.url, authorization: req.headers.authorization});
        res.end('bad');
      }).listen(BAD_PORT, done);
    });
  });

  afterEach(function (done) {
    goodServer.close(function () {
      badServer.close(function () {
        done();
      });
    });
  });

  function assertStayedOnBaseURL(response, expectedPath) {
    assert.strictEqual(response.data, 'good');
    assert.strictEqual(badServerRequests.length, 0);
    assert.strictEqual(goodServerRequests.length, 1);
    assert.strictEqual(goodServerRequests[0].url, expectedPath);
  }

  it('should not send the request or its credentials to an absolute URL when allowAbsoluteUrls is false', async function () {
    const instance = axios.create({
      baseURL: GOOD_BASE_URL,
      allowAbsoluteUrls: false,
      auth: AUTH
    });

    const response = await instance.get(BAD_URL);

    assertStayedOnBaseURL(response, '/' + BAD_URL);
    assert.ok(goodServerRequests[0].authorization);
  });

  it('should honour allowAbsoluteUrls = false set on the request config', async function () {
    const instance = axios.create({baseURL: GOOD_BASE_URL});

    const response = await instance.get(BAD_URL, {allowAbsoluteUrls: false});

    assertStayedOnBaseURL(response, '/' + BAD_URL);
  });

  it('should honour allowAbsoluteUrls = false set on the global defaults', async function () {
    axios.defaults.allowAbsoluteUrls = false;

    try {
      const response = await axios.get(BAD_URL, {baseURL: GOOD_BASE_URL});

      assertStayedOnBaseURL(response, '/' + BAD_URL);
    } finally {
      delete axios.defaults.allowAbsoluteUrls;
    }
  });

  it('should not send the request to a protocol-relative URL when allowAbsoluteUrls is false', async function () {
    const instance = axios.create({
      baseURL: GOOD_BASE_URL,
      allowAbsoluteUrls: false
    });

    const response = await instance.get('//localhost:' + String(BAD_PORT) + '/steal');

    assertStayedOnBaseURL(response, '/localhost:' + String(BAD_PORT) + '/steal');
  });

  it('should resolve getUri against the baseURL when allowAbsoluteUrls is false', function () {
    const instance = axios.create({
      baseURL: GOOD_BASE_URL,
      allowAbsoluteUrls: false
    });

    assert.strictEqual(instance.getUri({url: BAD_URL}), GOOD_BASE_URL + '/' + BAD_URL);
  });

  it('should not send the request to an absolute URL with the CommonJS build (dist/node/axios.cjs)', async function () {
    const axiosCjs = require('../../../dist/node/axios.cjs');

    const instance = axiosCjs.create({
      baseURL: GOOD_BASE_URL,
      allowAbsoluteUrls: false,
      auth: AUTH
    });

    const response = await instance.get(BAD_URL);

    assertStayedOnBaseURL(response, '/' + BAD_URL);
  });

  it('should keep sending requests to absolute URLs by default', async function () {
    const instance = axios.create({baseURL: GOOD_BASE_URL});

    const response = await instance.get(BAD_URL);

    assert.strictEqual(response.data, 'bad');
    assert.strictEqual(goodServerRequests.length, 0);
    assert.strictEqual(badServerRequests.length, 1);
  });
});

// The xhr adapter is exercised in real browsers by test/specs/options.spec.js. This suite runs the published
// browser CommonJS bundle against a minimal browser environment.
describe('Server-Side Request Forgery via absolute URL (CVE-2025-27152) - dist/browser/axios.cjs', function () {
  const BUNDLE_URL = new URL('../../../dist/browser/axios.cjs', import.meta.url);
  const ORIGIN = 'http://localhost:8080';
  const BASE_URL = 'http://api.example.com/';
  const EVIL_URL = 'http://evil.example.com/steal';

  let browserAxios;
  let requests;

  beforeEach(function () {
    requests = [];

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
      cookie: '',
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

    browserAxios = module.exports;
  });

  it('should not send the request to an absolute URL when allowAbsoluteUrls is false', async function () {
    const instance = browserAxios.create({
      baseURL: BASE_URL,
      allowAbsoluteUrls: false
    });

    await instance.get(EVIL_URL);

    assert.strictEqual(requests.length, 1);
    assert.strictEqual(requests[0].url, BASE_URL + EVIL_URL);
  });

  it('should keep sending requests to absolute URLs by default', async function () {
    const instance = browserAxios.create({baseURL: BASE_URL});

    await instance.get(EVIL_URL);

    assert.strictEqual(requests.length, 1);
    assert.strictEqual(requests[0].url, EVIL_URL);
  });
});
