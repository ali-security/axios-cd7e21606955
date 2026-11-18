"use strict";

import assert from "assert";
import http from "http";
import vm from "vm";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import validator from "../../../lib/helpers/validator.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";
import buildURL from "../../../lib/helpers/buildURL.js";

const nodeMajorVersion = parseInt(process.versions.node.split('.')[0], 10);

describe("Prototype Pollution Protection", function () {
  afterEach(function () {
    // Clean up any pollution that might have occurred
    delete Object.prototype.polluted;
    delete Object.prototype.transport;
    delete Object.prototype.transformRequest;
    delete Object.prototype.transformResponse;
    delete Object.prototype.formSerializer;
    delete Object.prototype.env;
    delete Object.prototype.parseReviver;
    delete Object.prototype.headers;
    delete Object.prototype.customObj;
    delete Object.prototype.adapter;
    delete Object.prototype.validateStatus;
    delete Object.prototype.transitional;
    delete Object.prototype.responseType;
    delete Object.prototype.response;
    delete Object.prototype.proxy;
    delete Object.prototype.auth;
    delete Object.prototype.username;
    delete Object.prototype.password;
    delete Object.prototype.hostname;
    delete Object.prototype.host;
    delete Object.prototype.port;
    delete Object.prototype.protocol;
    delete Object.prototype.get;
    delete Object.prototype.set;
    delete Object.prototype.options;
    delete Object.prototype.customNested;
    delete Object.prototype.baseURL;
    delete Object.prototype.socketPath;
    delete Object.prototype.beforeRedirect;
    delete Object.prototype.insecureHTTPParser;
    delete Object.prototype.httpAgent;
    delete Object.prototype.httpsAgent;
    delete Object.prototype.maxContentLength;
    delete Object.prototype.maxBodyLength;
    delete Object.prototype.maxRedirects;
    delete Object.prototype.maxRate;
    delete Object.prototype.timeout;
    delete Object.prototype.timeoutErrorMessage;
    delete Object.prototype.cancelToken;
    delete Object.prototype.signal;
    delete Object.prototype.decompress;
    delete Object.prototype.params;
    delete Object.prototype.paramsSerializer;
    delete Object.prototype.method;
    delete Object.prototype.withCredentials;
    delete Object.prototype.createConnection;
  });

  describe("utils.merge", function () {
    it("should filter __proto__ key at top level", function () {
      const result = utils.merge(
        {},
        { __proto__: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key at top level", function () {
      const result = utils.merge(
        {},
        { constructor: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key at top level", function () {
      const result = utils.merge(
        {},
        { prototype: { polluted: "yes" }, safe: "value" },
      );

      assert.strictEqual(result.safe, "value");
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter __proto__ key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            __proto__: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter constructor key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            constructor: { prototype: { polluted: "nested" } },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });

    it("should filter prototype key in nested objects", function () {
      const result = utils.merge(
        {},
        {
          headers: {
            prototype: { polluted: "nested" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in deeply nested objects", function () {
      const result = utils.merge(
        {},
        {
          level1: {
            level2: {
              __proto__: { polluted: "deep" },
              prototype: { polluted: "deep" },
              safe: "value",
            },
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.level1.level2.safe, "value");
      assert.strictEqual(
        result.level1.level2.hasOwnProperty("__proto__"),
        false,
      );
    });

    it("should still merge regular properties correctly", function () {
      const result = utils.merge({ a: 1, b: { c: 2 } }, { b: { d: 3 }, e: 4 });

      assert.strictEqual(result.a, 1);
      assert.strictEqual(result.b.c, 2);
      assert.strictEqual(result.b.d, 3);
      assert.strictEqual(result.e, 4);
    });

    it("should handle JSON.parse payloads safely", function () {
      const malicious = JSON.parse('{"__proto__": {"polluted": "yes"}}');
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
    });

    it("should handle nested JSON.parse payloads safely", function () {
      const malicious = JSON.parse(
        '{"headers": {"constructor": {"prototype": {"polluted": "yes"}}}}',
      );
      const result = utils.merge({}, malicious);

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers.hasOwnProperty("constructor"), false);
    });
  });

  describe("mergeConfig", function () {
    it("should filter dangerous keys at top level", function () {
      const result = mergeConfig(
        {},
        {
          __proto__: { polluted: "yes" },
          constructor: { polluted: "yes" },
          prototype: { polluted: "yes" },
          url: "/api/test",
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.url, "/api/test");
      assert.strictEqual(result.hasOwnProperty("__proto__"), false);
      assert.strictEqual(result.hasOwnProperty("constructor"), false);
      assert.strictEqual(result.hasOwnProperty("prototype"), false);
    });

    it("should filter dangerous keys in headers", function () {
      const result = mergeConfig(
        {},
        {
          headers: {
            __proto__: { polluted: "yes" },
            "Content-Type": "application/json",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.headers["Content-Type"], "application/json");
      assert.strictEqual(result.headers.hasOwnProperty("__proto__"), false);
    });

    it("should filter dangerous keys in custom config properties", function () {
      const result = mergeConfig(
        {},
        {
          customProp: {
            __proto__: { polluted: "yes" },
            safe: "value",
          },
        },
      );

      assert.strictEqual(Object.prototype.polluted, undefined);
      assert.strictEqual(result.customProp.safe, "value");
      assert.strictEqual(result.customProp.hasOwnProperty("__proto__"), false);
    });

    it("should still merge configs correctly", function () {
      const config1 = {
        baseURL: "https://api.example.com",
        timeout: 1000,
        headers: {
          common: {
            Accept: "application/json",
          },
        },
      };

      const config2 = {
        url: "/users",
        timeout: 5000,
        headers: {
          common: {
            "Content-Type": "application/json",
          },
        },
      };

      const result = mergeConfig(config1, config2);

      assert.strictEqual(result.baseURL, "https://api.example.com");
      assert.strictEqual(result.url, "/users");
      assert.strictEqual(result.timeout, 5000);
      assert.strictEqual(result.headers.common.Accept, "application/json");
      assert.strictEqual(
        result.headers.common["Content-Type"],
        "application/json",
      );
    });

    it("should not inherit transport from Object.prototype", function () {
      Object.prototype.transport = { request: function () {} };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(result.hasOwnProperty("transport"), false);
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transport"),
        false
      );
    });

    it("should not inherit transformRequest from Object.prototype", function () {
      Object.prototype.transformRequest = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformRequest"),
        false
      );
    });

    it("should not inherit transformResponse from Object.prototype", function () {
      Object.prototype.transformResponse = function () { return "hijacked"; };
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "transformResponse"),
        false
      );
    });

    it("should not inherit arbitrary keys from Object.prototype", function () {
      Object.prototype.polluted = "yes";
      const result = mergeConfig({}, { url: "/a" });
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result, "polluted"),
        false
      );
    });

    // The tests above only assert that polluted keys never become *own*
    // properties of the merged config. That is trivially true regardless of the
    // fix, because mergeConfig only iterates own keys, so a prototype-only key is
    // never visited. The tests below actually exercise the configValue guard:
    // when config2 owns a key that config1 lacks, the unguarded merge reads
    // `config1[prop]` off the polluted prototype and folds it into the result.

    it("should not fold prototype-inherited values into a merged headers key", function () {
      Object.prototype.headers = { polluted: "yes" };
      // config1 has no own `headers`; config2 does.
      const result = mergeConfig({}, { headers: { a: "1" } });
      assert.strictEqual(result.headers.a, "1");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.headers, "polluted"),
        false,
        "inherited Object.prototype.headers leaked into the merged headers"
      );
    });

    it("should not fold prototype-inherited values into a merged deep key", function () {
      Object.prototype.customObj = { polluted: "yes" };
      const result = mergeConfig({}, { customObj: { safe: "value" } });
      assert.strictEqual(result.customObj.safe, "value");
      assert.strictEqual(
        Object.prototype.hasOwnProperty.call(result.customObj, "polluted"),
        false,
        "inherited Object.prototype.customObj leaked into the merged value"
      );
    });

    // Merging against the real defaults: the defaults own these keys, the
    // request config does not, so an unguarded `config2[prop]` read resolves
    // the polluted Object.prototype value and it replaces the safe default.

    it("should not replace default transforms with ones inherited from Object.prototype", function () {
      const hijack = function () { return "hijacked"; };
      Object.prototype.transformRequest = hijack;
      Object.prototype.transformResponse = hijack;
      const result = mergeConfig(defaults, { url: "/a" });
      assert.notStrictEqual(result.transformRequest, hijack);
      assert.notStrictEqual(result.transformResponse, hijack);
      assert.deepStrictEqual(result.transformRequest, defaults.transformRequest);
      assert.deepStrictEqual(result.transformResponse, defaults.transformResponse);
    });

    it("should not replace the default adapter with one inherited from Object.prototype", function () {
      const hijack = function () {};
      Object.prototype.adapter = hijack;
      const result = mergeConfig(defaults, { url: "/a" });
      assert.notStrictEqual(result.adapter, hijack);
      assert.deepStrictEqual(result.adapter, defaults.adapter);
    });

    it("should not replace validateStatus with one inherited from Object.prototype", function () {
      Object.prototype.validateStatus = function () { return true; };
      const result = mergeConfig(defaults, { url: "/a" });
      assert.strictEqual(result.validateStatus, defaults.validateStatus);
    });
  });

  describe("defaults transforms", function () {
    it("should not use a formSerializer inherited from Object.prototype", function () {
      let hijacked = false;
      Object.prototype.formSerializer = {
        visitor: function () {
          hijacked = true;
          return false;
        }
      };
      const headers = new AxiosHeaders();
      headers.setContentType("application/x-www-form-urlencoded");
      const result = defaults.transformRequest[0].call({}, { a: "1" }, headers);
      assert.strictEqual(hijacked, false, "inherited Object.prototype.formSerializer was used");
      assert.strictEqual(result, "a=1");
    });

    it("should not use an env.FormData inherited from Object.prototype", function () {
      let hijacked = false;
      function EvilFormData() {
        hijacked = true;
      }
      EvilFormData.prototype.append = function () {};
      Object.prototype.env = { FormData: EvilFormData };
      const headers = new AxiosHeaders();
      headers.setContentType("multipart/form-data");
      defaults.transformRequest[0].call({}, { a: "1" }, headers);
      assert.strictEqual(hijacked, false, "inherited Object.prototype.env.FormData was used");
    });

    it("should not use transitional options inherited from Object.prototype", function () {
      Object.prototype.transitional = { forcedJSONParsing: false };
      const result = defaults.transformResponse[0].call({}, '{"a":1}');
      assert.deepStrictEqual(result, { a: 1 });
    });

    it("should not use a responseType inherited from Object.prototype", function () {
      Object.prototype.responseType = "text";
      const result = defaults.transformResponse[0].call({}, '{"a":1}');
      assert.deepStrictEqual(result, { a: 1 });
    });

    it("should not attach a response inherited from Object.prototype to parse errors", function () {
      Object.prototype.response = { status: 200, data: "polluted" };
      const config = {
        responseType: "json",
        transitional: { silentJSONParsing: false, forcedJSONParsing: true }
      };
      assert.throws(function () {
        defaults.transformResponse[0].call(config, "{not json");
      }, function (err) {
        return err.code === "ERR_BAD_RESPONSE" &&
          !Object.prototype.hasOwnProperty.call(err, "response");
      });
    });
  });

  function startServer(handler) {
    return new Promise((resolve) => {
      const server = http.createServer(handler || ((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ headers: req.headers, url: req.url }));
      }));
      server.listen(0, '127.0.0.1', () => resolve(server));
    });
  }

  function stopServer(server) {
    return new Promise((resolve) => server.close(resolve));
  }

  describe('http adapter setProxy', function () {
    it('should not inject Proxy-Authorization from polluted Object.prototype.auth', async function () {
      this.timeout(10000);
      // setProxy reads `proxy.auth` directly. When `proxy` is a
      // URL instance from the environment proxy or a plain object without an own `auth`,
      // a polluted Object.prototype.auth would otherwise be base64-encoded into the
      // Proxy-Authorization header, leaking attacker-controlled credentials.
      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.auth must not produce a Proxy-Authorization header'
        );
      } finally {
        delete Object.prototype.auth;
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should not inject Proxy-Authorization from polluted Object.prototype.username', async function () {
      this.timeout(10000);
      // The setProxy username/password branch builds basic creds from `proxy.username`
      // and `proxy.password`. For a plain object proxy, both reads must be guarded
      // against prototype pollution.
      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      Object.prototype.username = 'attacker';
      Object.prototype.password = 'exfil';

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, {
          proxy: { host: '127.0.0.1', port: proxyPort, protocol: 'http' },
        });
        assert.strictEqual(res.status, 200);
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          undefined,
          'polluted Object.prototype.username must not produce a Proxy-Authorization header'
        );
      } finally {
        delete Object.prototype.username;
        delete Object.prototype.password;
        await stopServer(target);
        await stopServer(proxy);
      }
    });

    it('should still build Proxy-Authorization from an own proxy auth object', async function () {
      this.timeout(10000);
      const proxy = await startServer();
      const { port: proxyPort } = proxy.address();

      const target = await startServer();
      const { port: targetPort } = target.address();

      const proxyConfig = {
        host: '127.0.0.1',
        port: proxyPort,
        protocol: 'http',
        auth: { username: 'user', password: 'pass' },
      };

      try {
        const res = await axios.get(`http://127.0.0.1:${targetPort}/api`, { proxy: proxyConfig });
        assert.strictEqual(
          res.data.headers['proxy-authorization'],
          'Basic ' + Buffer.from('user:pass', 'utf8').toString('base64')
        );
      } finally {
        await stopServer(target);
        await stopServer(proxy);
      }
    });
  });

  // utils.merge previously read `result[targetKey]` directly, which walks the
  // prototype chain. A polluted Object.prototype.<key> object would surface as
  // the existing value and be merged into the result.
  describe('utils.merge prototype-chain read', function () {
    it('should not pick up polluted Object.prototype.<key> as the existing value', function () {
      Object.prototype.headers = { evil: 'yes' };

      const result = utils.merge({}, { headers: { 'Content-Type': 'application/json' } });

      assert.strictEqual(result.headers.evil, undefined);
      assert.strictEqual(result.headers['Content-Type'], 'application/json');
    });

    it('should not absorb polluted nested objects when the key is absent from inputs', function () {
      // When the source does not carry `customNested`, the merged result should
      // not surface it either, even if Object.prototype carries it.
      Object.prototype.customNested = { evil: 'yes' };

      const result = utils.merge({}, { safe: 'value' });

      assert.strictEqual(Object.prototype.hasOwnProperty.call(result, 'customNested'), false);
      assert.strictEqual(result.safe, 'value');
    });
  });

  // Object.defineProperty calls a HasProperty check on `get`/`set` of the
  // descriptor. A polluted Object.prototype.get with a non-function value would
  // throw TypeError at every defineProperty site that uses a plain literal
  // descriptor. Each fixed site should be shielded with `__proto__: null`.
  describe('Object.defineProperty descriptor literals', function () {
    it('should construct AxiosHeaders accessor methods when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // AxiosHeaders.accessor uses Object.defineProperty on the prototype.
      // Triggering a fresh accessor definition exercises the descriptor literal.
      AxiosHeaders.accessor('X-Pp-Test');

      delete Object.prototype.get;

      const h = new AxiosHeaders();
      h.setXPpTest('value');
      assert.strictEqual(h.getXPpTest(), 'value');
    });

    it('should not throw in mergeConfig when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      const result = mergeConfig({}, { url: '/x', method: 'get' });

      delete Object.prototype.get;

      assert.strictEqual(result.url, '/x');
      assert.strictEqual(result.method, 'get');
      assert.strictEqual(typeof result.hasOwnProperty, 'function');
    });

    it('should not throw in utils.inherits when Object.prototype.get is polluted', function () {
      function Parent() {}
      function Child() {}

      Object.prototype.get = 'attacker';

      utils.inherits(Child, Parent);

      delete Object.prototype.get;

      assert.strictEqual(Child.prototype.constructor, Child);
      assert.strictEqual(Child.super, Parent.prototype);
    });

    it('should not throw in utils.extend / axios.create when Object.prototype.get is polluted', function () {
      Object.prototype.get = 'attacker';

      // axios.create copies the Axios prototype methods onto the instance via
      // utils.extend, which uses Object.defineProperty with literal descriptors.
      const instance = axios.create();

      delete Object.prototype.get;

      assert.strictEqual(typeof instance.request, 'function');
      assert.strictEqual(typeof instance.get, 'function');
    });

    it('should also be shielded against a polluted Object.prototype.set', function () {
      Object.prototype.set = 'attacker';

      // Same surface as `get` — ToPropertyDescriptor checks both. One spot-check
      // covers them all since they share the same fix.
      const result = mergeConfig({}, { url: '/y' });
      utils.inherits(function Child() {}, function Parent() {});

      delete Object.prototype.set;

      assert.strictEqual(result.url, '/y');
    });

    it('should prepare request headers without descriptor errors when get and set are polluted', async function () {
      let seenAccept;
      Object.prototype.get = function () {};
      Object.prototype.set = function () {};

      try {
        const instance = axios.create({
          adapter: function adapter(config) {
            seenAccept = config.headers.Accept;
            return Promise.resolve({
              data: null,
              status: 200,
              statusText: 'OK',
              headers: {},
              config: config
            });
          },
          headers: {
            common: {
              Accept: 'application/json'
            }
          }
        });

        await instance.get('/users');
      } finally {
        delete Object.prototype.get;
        delete Object.prototype.set;
      }

      assert.strictEqual(seenAccept, 'application/json');
    });
  });

  describe('Axios request header buckets', function () {
    it('should not merge a polluted Object.prototype[method] bucket into request headers', async function () {
      let seenHeaders;
      const instance = axios.create({
        adapter: function adapter(config) {
          seenHeaders = config.headers;
          return Promise.resolve({
            data: null,
            status: 200,
            statusText: 'OK',
            headers: {},
            config: config
          });
        }
      });

      // `options` has no bucket in the defaults, so an unguarded
      // `headers[config.method]` read resolves the polluted prototype value.
      Object.prototype.options = { 'X-Polluted': 'yes' };

      try {
        await instance.request({ url: '/users', method: 'options' });
      } finally {
        delete Object.prototype.options;
      }

      assert.strictEqual(seenHeaders.get('X-Polluted'), undefined);
    });
  });

  // End-to-end regressions covering published advisory PoCs against full axios
  // request flow. Each test mirrors the exploit scenario from the advisory and
  // asserts the attack does not succeed.
  describe('advisory regression — full request flow', function () {
    // Full MITM via prototype pollution gadget in
    // `config.proxy`. The http adapter must not surface a polluted
    // Object.prototype.proxy as the request's proxy, otherwise every request
    // would route through an attacker-controlled host.
    it('polluted Object.prototype.proxy must not redirect requests through an attacker proxy', async function () {
      this.timeout(10000);
      const proxyHits = [];
      const attackerProxy = await startServer((req, res) => {
        proxyHits.push({
          url: req.url,
          authorization: req.headers.authorization,
          host: req.headers.host,
        });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });

      const realHits = [];
      const realServer = await startServer((req, res) => {
        realHits.push({ url: req.url });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"data":"real"}');
      });

      try {
        Object.prototype.proxy = {
          protocol: 'http',
          host: '127.0.0.1',
          port: attackerProxy.address().port,
        };

        const realPort = realServer.address().port;
        const res = await axios.get(`http://127.0.0.1:${realPort}/api/secrets`, {
          auth: { username: 'admin', password: 'SuperSecret123!' },
        });

        assert.strictEqual(proxyHits.length, 0, 'attacker proxy must not receive any request');
        assert.strictEqual(realHits.length, 1, 'request must reach the real target');
        assert.deepStrictEqual(res.data, { data: 'real' });
      } finally {
        delete Object.prototype.proxy;
        await stopServer(attackerProxy);
        await stopServer(realServer);
      }
    });

    // Credential theft and response hijacking via
    // prototype pollution gadget in config merge. A polluted
    // Object.prototype.transformResponse function would otherwise execute with
    // `this = config`, exposing `auth.username`/`auth.password` to the attacker.
    it('polluted Object.prototype.transformResponse must not be invoked or leak request credentials', async function () {
      this.timeout(10000);
      let invoked = false;
      let stolen = null;

      const server = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"secret":"keep-me"}');
      });

      Object.prototype.transformResponse = function pollutedTransform(data) {
        invoked = true;
        stolen = {
          url: this && this.url,
          username: this && this.auth && this.auth.username,
          password: this && this.auth && this.auth.password,
          data,
        };
        return true;
      };

      try {
        const { port } = server.address();
        const res = await axios.get(`http://127.0.0.1:${port}/users`, {
          auth: { username: 'svc-account', password: 'prod-secret-key-123!' },
        });

        assert.strictEqual(invoked, false, 'polluted transformResponse must not run');
        assert.strictEqual(stolen, null, 'no request context must be captured');
        assert.deepStrictEqual(
          res.data,
          { secret: 'keep-me' },
          'response data must reach the caller untampered'
        );
      } finally {
        delete Object.prototype.transformResponse;
        await stopServer(server);
      }
    });
  });

  // GHSA-q8qp-cvcw-x6jj: five config properties were read via direct property
  // access in the http adapter and request-config resolution, bypassing
  // hasOwnProperty and allowing prototype pollution gadgets (auth, baseURL,
  // socketPath, beforeRedirect, insecureHTTPParser).
  describe('GHSA-q8qp-cvcw-x6jj http adapter gadgets', function () {
    it('should not pick up Object.prototype.auth as an Authorization header', async function () {
      this.timeout(10000);
      Object.prototype.auth = { username: 'attacker', password: 'exfil' };

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.data.headers.authorization, undefined);
      } finally {
        await stopServer(server);
      }
    });

    it('should not pick up Object.prototype.socketPath and redirect the request', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      const server = await startServer();
      const { port } = server.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${port}/api`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.data.url, '/api');
      } finally {
        await stopServer(server);
      }
    });

    it('should not invoke Object.prototype.beforeRedirect during redirects', async function () {
      this.timeout(10000);
      let hijackCalled = false;
      Object.prototype.beforeRedirect = function polluted() {
        hijackCalled = true;
      };

      const target = await startServer();
      const { port: targetPort } = target.address();

      const redirector = await startServer((req, res) => {
        res.writeHead(302, { Location: `http://127.0.0.1:${targetPort}/final` });
        res.end();
      });
      const { port: redirectorPort } = redirector.address();

      try {
        const res = await axios.get(`http://127.0.0.1:${redirectorPort}/start`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(hijackCalled, false);
      } finally {
        await stopServer(redirector);
        await stopServer(target);
      }
    });

    it('should not enable insecureHTTPParser via Object.prototype', async function () {
      if (nodeMajorVersion < 14) this.skip();
      this.timeout(10000);
      // A raw TCP server emits a response that uses LF-only line terminators
      // instead of CRLF. Node's strict HTTP parser rejects this payload; the
      // insecure parser accepts it. If Object.prototype.insecureHTTPParser were
      // picked up, the request would succeed. The request must fail when the
      // gadget is properly blocked.
      Object.prototype.insecureHTTPParser = true;

      const net = await import('net');
      const malformedPayload =
        'HTTP/1.1 200 OK\n' +
        'Content-Type: application/json\n' +
        'Content-Length: 2\n' +
        '\n' +
        '{}';
      const malformed = await new Promise((resolve) => {
        const srv = net.createServer((socket) => {
          socket.once('data', () => socket.end(malformedPayload));
        });
        srv.listen(0, '127.0.0.1', () => resolve(srv));
      });
      const { port } = malformed.address();

      try {
        let threw = false;
        let caughtCode = '';
        try {
          await axios.get(`http://127.0.0.1:${port}/`, {
            transitional: { clarifyTimeoutError: false },
          });
        } catch (err) {
          threw = true;
          caughtCode = String(err && (err.code || err.message));
        }
        assert.strictEqual(
          threw,
          true,
          `request should be rejected by the strict HTTP parser (got: ${caughtCode || 'success'})`
        );
        // The exact llhttp code for LF-only line terminators varies across
        // Node versions. Match any parser error to remain stable across Node
        // releases while still confirming the strict parser rejected the payload.
        assert.ok(
          /^HPE_/.test(caughtCode),
          `expected an HPE_* parser error, got: ${caughtCode}`
        );
      } finally {
        await new Promise((resolve) => malformed.close(resolve));
      }
    });

    it('should not pass insecureHTTPParser: true to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.insecureHTTPParser = true;

      let capturedValue;
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedValue = options.insecureHTTPParser;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {
      } finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedValue, false);
    });

    it('should not pass a polluted socketPath to http.request via Object.prototype', async function () {
      this.timeout(10000);
      Object.prototype.socketPath = '/tmp/axios-should-never-be-used.sock';

      let capturedSocketPath = 'not-called';
      const origRequest = http.request;
      http.request = function(options, callback) {
        capturedSocketPath = options.socketPath;
        return origRequest.apply(this, arguments);
      };

      const server = await startServer();
      const { port } = server.address();
      try {
        await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
      } catch (_) {
      } finally {
        http.request = origRequest;
        await stopServer(server);
      }

      assert.strictEqual(capturedSocketPath, undefined);
    });

    it('should pass an own inert createConnection option to transports', async function () {
      this.timeout(10000);
      Object.prototype.createConnection = function () {
        throw new Error('unexpected inherited createConnection');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`, {
          transport: {
            request(options, handleResponse) {
              assert.strictEqual(
                Object.prototype.hasOwnProperty.call(options, 'createConnection'),
                true
              );
              assert.strictEqual(options.createConnection, undefined);
              return http.request(options, handleResponse);
            }
          }
        });

        assert.strictEqual(response.data, 'ok');
      } finally {
        await stopServer(server);
      }
    });

    it('should not open the socket through Object.prototype.createConnection (native transport)', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.createConnection = function () {
        hijacked = true;
        throw new Error('polluted createConnection must not be used');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`, { maxRedirects: 0 });
        assert.strictEqual(response.data, 'ok');
      } finally {
        await stopServer(server);
      }

      assert.strictEqual(hijacked, false);
    });

    it('should not open the socket through Object.prototype.createConnection (follow-redirects transport)', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.createConnection = function () {
        hijacked = true;
        throw new Error('polluted createConnection must not be used');
      };

      const server = await startServer((req, res) => res.end('ok'));
      const { port } = server.address();

      try {
        const response = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(response.data, 'ok');
      } finally {
        await stopServer(server);
      }

      assert.strictEqual(hijacked, false);
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj baseURL gadget', function () {
    // The baseURL branch in buildFullPath only runs when the requested URL is
    // relative (or allowAbsoluteUrls === false). We therefore issue a relative
    // GET and assert that the request fails (no host to resolve) because
    // baseURL is correctly absent from the merged config, and that the
    // polluted hijacker is never hit.
    it('should not hijack relative-URL requests via Object.prototype.baseURL', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = await startServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      const { port: hijackerPort } = hijacker.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get('/api');
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        assert.strictEqual(threw, true);
      } finally {
        await stopServer(hijacker);
      }
    });

    // Second variant using allowAbsoluteUrls: false to force the baseURL path
    // even for a fully-qualified requested URL.
    it('should not hijack requests via Object.prototype.baseURL with allowAbsoluteUrls:false', async function () {
      this.timeout(10000);
      let hijackHit = false;
      const hijacker = await startServer((req, res) => {
        hijackHit = true;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"hijacked":true}');
      });
      const { port: hijackerPort } = hijacker.address();

      const target = await startServer((req, res) => {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end('{"ok":true}');
      });
      const { port: targetPort } = target.address();

      Object.prototype.baseURL = `http://127.0.0.1:${hijackerPort}`;

      try {
        let threw = false;
        try {
          await axios.get(`http://127.0.0.1:${targetPort}/api`, {
            allowAbsoluteUrls: false,
          });
        } catch (_err) {
          threw = true;
        }
        assert.strictEqual(hijackHit, false);
        // allowAbsoluteUrls:false + no baseURL -> combineURLs not invoked
        // (baseURL falsy) -> returns requested URL as-is -> target receives it.
        assert.strictEqual(threw, false);
      } finally {
        await stopServer(hijacker);
        await stopServer(target);
      }
    });

    it('should not prefix getUri() with Object.prototype.baseURL', function () {
      Object.prototype.baseURL = 'http://evil.example.com';
      assert.strictEqual(axios.getUri({ url: '/api' }), '/api');
    });
  });

  describe('GHSA-q8qp-cvcw-x6jj validator.assertOptions schema lookup', function () {
    it('should not read a validator from a polluted Object.prototype key', function () {
      Object.prototype.pollutedOption = 'not-a-function';
      try {
        assert.doesNotThrow(function () {
          validator.assertOptions({ pollutedOption: true }, {}, true);
        });
      } finally {
        delete Object.prototype.pollutedOption;
      }
    });
  });

  // Structural defense: mergeConfig returns a null-prototype object, so any
  // property read that is not an own property of config cannot inherit from
  // Object.prototype. Adding a new key to Object.prototype must never appear
  // as a property of the merged config.
  describe('mergeConfig null-prototype structural defense', function () {
    it('should return an object whose prototype is null', function () {
      const merged = mergeConfig({ url: '/x' }, { method: 'get' });
      assert.strictEqual(Object.getPrototypeOf(merged), null);
    });

    it('should preserve hasOwnProperty as a callable own slot', function () {
      const merged = mergeConfig({}, { url: '/x', method: 'get' });
      assert.strictEqual(typeof merged.hasOwnProperty, 'function');
      assert.strictEqual(merged.hasOwnProperty('url'), true);
      assert.strictEqual(merged.hasOwnProperty('method'), true);
      assert.strictEqual(merged.hasOwnProperty('bogus'), false);
    });

    it('should not serialize hasOwnProperty slot via Object.keys', function () {
      const merged = mergeConfig({ url: '/x' }, {});
      assert.ok(Object.keys(merged).indexOf('hasOwnProperty') === -1);
    });

    it('should not expose arbitrary polluted keys as inherited properties', function () {
      Object.prototype.polluted = 'attacker';
      try {
        const merged = mergeConfig({ url: '/x' }, {});
        assert.strictEqual(merged.polluted, undefined);
      } finally {
        delete Object.prototype.polluted;
      }
    });
  });

  describe('dispatch config compatibility', function () {
    it('should preserve an unchanged merged config through dispatch', async function () {
      let interceptedConfig;
      let adapterConfig;

      const instance = axios.create({
        adapter: async (config) => {
          adapterConfig = config;
          return {
            data: 'ok',
            status: 200,
            statusText: 'OK',
            headers: {},
            config
          };
        }
      });

      instance.interceptors.request.use((config) => {
        interceptedConfig = config;
        return config;
      });

      const response = await instance.get('/config-identity');

      assert.strictEqual(adapterConfig, interceptedConfig);
      assert.strictEqual(response.config, interceptedConfig);
      assert.strictEqual(Object.getPrototypeOf(adapterConfig), null);
      assert.strictEqual(
        Object.prototype.propertyIsEnumerable.call(adapterConfig, 'hasOwnProperty'),
        false
      );
      assert.strictEqual(Object.keys(adapterConfig).includes('hasOwnProperty'), false);
    });

    it('should materialize a frozen null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: 'ok',
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.freeze(Object.assign(Object.create(null), config));
        return replacement;
      });

      const response = await instance.get('/frozen-replacement');

      assert.strictEqual(response.data, 'ok');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.isFrozen(response.config), false);
    });

    it('should filter unsafe keys from a null-prototype interceptor replacement', async function () {
      let replacement;

      const instance = axios.create({
        adapter: async (config) => ({
          data: {
            safe: config.safe,
            hasProto: Object.prototype.hasOwnProperty.call(config, '__proto__'),
            hasConstructor: Object.prototype.hasOwnProperty.call(config, 'constructor'),
            hasPrototype: Object.prototype.hasOwnProperty.call(config, 'prototype')
          },
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = Object.assign(Object.create(null), config);
        replacement.safe = 'preserved';
        Object.defineProperty(replacement, '__proto__', {
          value: 'excluded',
          enumerable: true,
          configurable: true,
          writable: true
        });
        replacement.constructor = 'excluded';
        replacement.prototype = 'excluded';
        return replacement;
      });

      const response = await instance.get('/unsafe-own-keys');

      assert.deepStrictEqual(response.data, {
        safe: 'preserved',
        hasProto: false,
        hasConstructor: false,
        hasPrototype: false
      });
      assert.notStrictEqual(response.config, replacement);
    });

    it('should normalize a class-based interceptor replacement', async function () {
      let replacement;

      class ConfigTemplate {
        marker() {
          return 'template';
        }
      }

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.marker(),
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        replacement = new ConfigTemplate();
        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;
        replacement.adapter = config.adapter;
        return replacement;
      });

      const response = await instance.get('/normalized-replacement');

      assert.strictEqual(response.data, 'template');
      assert.notStrictEqual(response.config, replacement);
      assert.strictEqual(response.config instanceof ConfigTemplate, false);
      assert.strictEqual(Object.getPrototypeOf(response.config), null);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(response.config, 'marker'), true);
    });
  });

  // Verify every gadget enumerated in the audit (extension of GHSA-q8qp-cvcw-x6jj)
  // is neutralized end-to-end by the null-prototype config.
  describe('Full gadget coverage via null-prototype config', function () {
    function startEcho() {
      return startServer((req, res) => {
        let body = '';
        req.on('data', (c) => (body += c));
        req.on('end', () => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({
            url: req.url,
            method: req.method,
            headers: req.headers,
            body,
          }));
        });
      });
    }

    it('should ignore polluted transformRequest', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformRequest = function polluted(data) {
        invoked = true;
        return 'INJECTED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.post(`http://127.0.0.1:${port}/`, { hello: 'world' });
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data.body, 'INJECTED');
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted transformResponse', async function () {
      this.timeout(10000);
      let invoked = false;
      Object.prototype.transformResponse = function polluted() {
        invoked = true;
        return 'HIJACKED';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(invoked, false);
        assert.notStrictEqual(res.data, 'HIJACKED');
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted adapter', async function () {
      this.timeout(10000);
      let hijacked = false;
      Object.prototype.adapter = function pollutedAdapter() {
        hijacked = true;
        return Promise.resolve({ data: 'pwned', status: 200, statusText: 'OK', headers: {}, config: {}, request: {} });
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(hijacked, false);
        assert.notStrictEqual(res.data, 'pwned');
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted httpAgent', async function () {
      this.timeout(10000);
      let agentUsed = false;
      Object.prototype.httpAgent = new http.Agent({
        keepAlive: false,
      });
      // Wrap createConnection to detect usage
      const origCreate = Object.prototype.httpAgent.createConnection;
      Object.prototype.httpAgent.createConnection = function () {
        agentUsed = true;
        return origCreate.apply(this, arguments);
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
        assert.strictEqual(agentUsed, false);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted proxy', async function () {
      this.timeout(10000);
      Object.prototype.proxy = {
        protocol: 'http',
        host: '127.0.0.1',
        port: 1, // would fail if actually used
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted maxContentLength', async function () {
      this.timeout(10000);
      // Polluted tiny limit would reject a normal response if applied.
      Object.prototype.maxContentLength = 1;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted maxRedirects', async function () {
      this.timeout(10000);
      // Pollute with 0 — if picked up, follow-redirects path would be skipped.
      // We make sure regular requests still succeed via the expected path.
      Object.prototype.maxRedirects = 0;

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted timeout at the merged config level', function () {
      Object.prototype.timeout = 1;
      const merged = mergeConfig({}, { url: '/x' });
      assert.strictEqual(Object.prototype.hasOwnProperty.call(merged, 'timeout'), false);
      assert.strictEqual(merged.timeout, undefined);
    });

    it('should ignore polluted timeoutErrorMessage', async function () {
      this.timeout(10000);
      Object.prototype.timeoutErrorMessage = 'INJECTED_TIMEOUT';
      // Not easy to assert without triggering a real timeout; just confirm
      // normal requests still succeed and do not read the polluted key.
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted transitional', async function () {
      this.timeout(10000);
      Object.prototype.transitional = { forcedJSONParsing: true, silentJSONParsing: false };
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted params and paramsSerializer', async function () {
      this.timeout(10000);
      let serializerInvoked = false;
      Object.prototype.params = { injected: 'yes' };
      Object.prototype.paramsSerializer = function polluted() {
        serializerInvoked = true;
        return 'injected=yes';
      };

      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/x`);
        assert.strictEqual(serializerInvoked, false);
        assert.strictEqual(res.data.url, '/x');
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted method', async function () {
      this.timeout(10000);
      Object.prototype.method = 'DELETE';
      const server = await startEcho();
      const { port } = server.address();
      try {
        // axios.get should still send GET, not DELETE.
        const res = await axios.get(`http://127.0.0.1:${port}/ok`);
        assert.strictEqual(res.data.method, 'GET');
      } finally {
        await stopServer(server);
      }
    });

    it('should use GET when the default instance has no own method', async function () {
      Object.prototype.method = 'DELETE';

      const response = await axios({
        url: '/default-method',
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      assert.strictEqual(response.data, 'get');
    });

    it('should ignore headers inherited after a request interceptor replaces config', async function () {
      Object.prototype.headers = { 'X-Injected': 'yes' };

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.headers.get('X-Injected'),
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.headers;
        return replacement;
      });

      const response = await instance.get('/interceptor-headers');

      assert.strictEqual(response.data, undefined);
    });

    it('should ignore behavior inherited after a request interceptor replaces config', async function () {
      let requestTransformCalled = false;
      let responseTransformCalled = false;

      Object.prototype.transformRequest = () => {
        requestTransformCalled = true;
      };
      Object.prototype.transformResponse = () => {
        responseTransformCalled = true;
      };
      Object.prototype.cancelToken = {
        throwIfRequested() {
          throw new Error('unexpected inherited cancelToken');
        }
      };
      Object.prototype.signal = { aborted: true };
      Object.prototype.method = 'delete';

      const instance = axios.create({
        adapter: async (config) => ({
          data: config.method,
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        })
      });

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.transformRequest;
        delete replacement.transformResponse;
        delete replacement.cancelToken;
        delete replacement.signal;
        delete replacement.method;
        return replacement;
      });

      const response = await instance.get('/interceptor-behavior');

      assert.strictEqual(requestTransformCalled, false);
      assert.strictEqual(responseTransformCalled, false);
      assert.strictEqual(response.data, undefined);
    });

    it('should ignore an adapter inherited after a request interceptor replaces config', async function () {
      let called = false;

      Object.prototype.adapter = async (config) => {
        called = true;
        return {
          data: 'unexpected',
          status: 200,
          statusText: 'OK',
          headers: {},
          config
        };
      };

      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = { ...config };
        delete replacement.adapter;
        return replacement;
      });

      const response = await instance.get(
        'data:text/plain;base64,' + Buffer.from('safe').toString('base64'),
        { responseType: 'text' }
      );

      assert.strictEqual(called, false);
      assert.strictEqual(response.data, 'safe');
    });

    it('should preserve config inherited from a non-shared prototype after interception', async function () {
      const instance = axios.create();

      instance.interceptors.request.use((config) => {
        const replacement = Object.create({
          adapter: async (resolvedConfig) => ({
            data: resolvedConfig.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config: resolvedConfig
          }),
          customValue: 'preserved'
        });

        replacement.url = config.url;
        replacement.method = config.method;
        replacement.headers = config.headers;

        return replacement;
      });

      const response = await instance.get('/prototype-template');

      assert.strictEqual(response.data, 'preserved');
    });

    [
      ['unchanged', ''],
      ['set to null', 'Object.prototype.constructor = null;'],
      ['deleted', 'delete Object.prototype.constructor;'],
      [
        'replaced by an accessor',
        `Object.defineProperty(Object.prototype, 'constructor', {
          configurable: true,
          get() { return Object; }
        });`
      ]
    ].forEach(([description, mutateConstructor]) => {
      it(`should exclude a foreign realm Object.prototype with its constructor ${description}`, async function () {
        const context = vm.createContext({
          adapter: async (config) => ({
            data: config.customValue,
            status: 200,
            statusText: 'OK',
            headers: {},
            config
          })
        });

        const replacement = vm.runInContext(
          `
            Object.prototype.transformResponse = () => 'polluted';
            ${mutateConstructor}
            Object.create({adapter, customValue: 'preserved'});
          `,
          context
        );

        const instance = axios.create();

        instance.interceptors.request.use((config) => {
          replacement.url = config.url;
          replacement.method = config.method;
          replacement.headers = config.headers;

          return replacement;
        });

        const response = await instance.get('/cross-realm-prototype-template');

        assert.strictEqual(response.data, 'preserved');
      });
    });

    it('should ignore polluted decompress', async function () {
      this.timeout(10000);
      Object.prototype.decompress = false;
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        assert.strictEqual(res.status, 200);
      } finally {
        await stopServer(server);
      }
    });

    it('should ignore polluted responseType', async function () {
      this.timeout(10000);
      Object.prototype.responseType = 'arraybuffer';
      const server = await startEcho();
      const { port } = server.address();
      try {
        const res = await axios.get(`http://127.0.0.1:${port}/`);
        // When responseType is not set on config, json parsing should apply
        // and res.data should be an object, not an ArrayBuffer/Buffer.
        assert.strictEqual(typeof res.data, 'object');
        assert.ok(!Buffer.isBuffer(res.data));
      } finally {
        await stopServer(server);
      }
    });
  });

  // GHSA-7q8q-rj6j-mhjq (CVE-2026-67319): nested option objects such as
  // `auth: {}` and `paramsSerializer: {}` are cloned into ordinary objects by
  // mergeConfig, so reading their fields with plain dotted access picked up
  // values injected onto a polluted Object.prototype (Basic Authorization
  // header injection, query-string tampering).
  describe('GHSA-7q8q-rj6j-mhjq nested option objects', function () {
    const pollutedKeys = ['username', 'password', 'serialize', 'encode'];

    function pollute(key, value) {
      Object.defineProperty(Object.prototype, key, {
        value,
        configurable: true,
        writable: true
      });
    }

    afterEach(function () {
      pollutedKeys.forEach((key) => {
        delete Object.prototype[key];
      });
    });

    describe('utils.getSafeProp / utils.hasOwnInPrototypeChain', function () {
      it('should honor own properties', function () {
        assert.strictEqual(utils.hasOwnInPrototypeChain({ username: 'own' }, 'username'), true);
        assert.strictEqual(utils.getSafeProp({ username: 'own' }, 'username'), 'own');
      });

      it('should honor members inherited from a non-Object.prototype source', function () {
        class Serializer {
          serialize() {
            return 'class=1';
          }
        }
        const template = { encode() {} };

        assert.strictEqual(utils.getSafeProp(new Serializer(), 'serialize'), Serializer.prototype.serialize);
        assert.strictEqual(utils.getSafeProp(Object.create(template), 'encode'), template.encode);
      });

      it('should ignore values reachable only through a polluted Object.prototype', function () {
        pollute('username', 'inherited-user');

        // sanity: the pollution primitive is active for plain dotted reads
        assert.strictEqual({}.username, 'inherited-user');

        assert.strictEqual(utils.hasOwnInPrototypeChain({}, 'username'), false);
        assert.strictEqual(utils.getSafeProp({}, 'username'), undefined);
        assert.strictEqual(utils.getSafeProp(function () {}, 'username'), undefined);
      });

      it('should tolerate nullish and null-prototype inputs', function () {
        const bare = Object.create(null);
        bare.username = 'own';

        assert.strictEqual(utils.getSafeProp(null, 'username'), undefined);
        assert.strictEqual(utils.getSafeProp(undefined, 'username'), undefined);
        assert.strictEqual(utils.getSafeProp(bare, 'username'), 'own');
        assert.strictEqual(utils.getSafeProp(Object.create(null), 'username'), undefined);
      });

      it('should stop prototype-chain walks on cyclic Proxy prototypes', function () {
        let calls = 0;
        const proxy = new Proxy({}, {
          getPrototypeOf() {
            calls += 1;
            if (calls > 5) {
              throw new Error('cycled');
            }
            return proxy;
          }
        });

        assert.strictEqual(utils.hasOwnInPrototypeChain(proxy, 'missing'), false);
        assert.strictEqual(utils.getSafeProp(proxy, 'missing'), undefined);
        assert.ok(calls <= 2, 'prototype chain walk must stop on a cycle');
      });
    });

    describe('buildURL', function () {
      it('should ignore inherited serialize and encode on an empty options object', function () {
        let serializeInvoked = false;
        let encodeInvoked = false;

        pollute('serialize', function () {
          serializeInvoked = true;
          return 'polluted=1';
        });
        pollute('encode', function () {
          encodeInvoked = true;
          return 'polluted';
        });

        assert.strictEqual(buildURL('/foo', { value: 'a b' }, {}), '/foo?value=a+b');
        assert.strictEqual(serializeInvoked, false);
        assert.strictEqual(encodeInvoked, false);
      });

      it('should still use own and class-provided serialize/encode options', function () {
        class ClassSerializer {
          serialize(params) {
            return 'class=' + params.a;
          }
        }

        pollute('serialize', function () {
          return 'polluted=1';
        });

        assert.strictEqual(buildURL('/foo', { a: 1 }, { serialize: () => 'own=1' }), '/foo?own=1');
        assert.strictEqual(buildURL('/foo', { a: 'b' }, { encode: (v) => 'x' + v }), '/foo?xa=xb');
        assert.strictEqual(buildURL('/foo', { a: 1 }, new ClassSerializer()), '/foo?class=1');
      });
    });

    describe('axios.getUri', function () {
      it('should ignore inherited serialize and encode on an empty paramsSerializer', function () {
        let invoked = false;

        pollute('serialize', function () {
          invoked = true;
          return 'polluted=1';
        });
        pollute('encode', function () {
          invoked = true;
          return 'polluted';
        });

        assert.strictEqual(
          axios.getUri({ url: '/foo', params: { value: 'a b' }, paramsSerializer: {} }),
          '/foo?value=a+b'
        );
        assert.strictEqual(invoked, false);
      });
    });

    describe('http adapter', function () {
      it('should not build Basic auth from inherited username/password on an empty auth object', async function () {
        this.timeout(10000);
        pollute('username', 'attacker');
        pollute('password', 'exfil');

        const server = await startServer();
        const { port } = server.address();

        try {
          const res = await axios.get(`http://127.0.0.1:${port}/demo`, { auth: {} });
          assert.strictEqual(
            res.data.headers.authorization,
            'Basic ' + Buffer.from(':', 'utf8').toString('base64')
          );
        } finally {
          await stopServer(server);
        }
      });

      it('should still send own auth credentials when Object.prototype is polluted', async function () {
        this.timeout(10000);
        pollute('username', 'attacker');
        pollute('password', 'exfil');

        const server = await startServer();
        const { port } = server.address();

        try {
          const res = await axios.get(`http://127.0.0.1:${port}/demo`, {
            auth: { username: 'Aladdin', password: 'open sesame' }
          });
          assert.strictEqual(
            res.data.headers.authorization,
            'Basic ' + Buffer.from('Aladdin:open sesame', 'utf8').toString('base64')
          );
        } finally {
          await stopServer(server);
        }
      });

      it('should not let an inherited serialize tamper with the query string', async function () {
        this.timeout(10000);
        let serializeInvoked = false;

        pollute('serialize', function () {
          serializeInvoked = true;
          return 'polluted=1';
        });

        const server = await startServer();
        const { port } = server.address();

        try {
          const res = await axios.get(`http://127.0.0.1:${port}/demo`, {
            params: { value: 'a b' },
            paramsSerializer: {}
          });
          assert.strictEqual(res.data.url, '/demo?value=a+b');
          assert.strictEqual(serializeInvoked, false);
        } finally {
          await stopServer(server);
        }
      });

      it('should neutralize the advisory proof of concept (auth + paramsSerializer)', async function () {
        this.timeout(10000);
        pollute('username', 'attacker');
        pollute('password', 'exfil');
        pollute('serialize', function () {
          return 'polluted=1';
        });

        const server = await startServer();
        const { port } = server.address();

        try {
          const res = await axios.get(`http://127.0.0.1:${port}/demo`, {
            auth: {},
            paramsSerializer: {},
            params: { unused: 'ignored' }
          });
          assert.notStrictEqual(
            res.data.headers.authorization,
            'Basic ' + Buffer.from('attacker:exfil', 'utf8').toString('base64')
          );
          assert.strictEqual(res.data.url, '/demo?unused=ignored');
        } finally {
          await stopServer(server);
        }
      });
    });
  });
});
