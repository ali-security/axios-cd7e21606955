"use strict";

import assert from "assert";
import http from "http";
import axios from "../../../index.js";
import utils from "../../../lib/utils.js";
import mergeConfig from "../../../lib/core/mergeConfig.js";
import defaults from "../../../lib/defaults/index.js";
import AxiosHeaders from "../../../lib/core/AxiosHeaders.js";

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
});
