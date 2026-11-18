"use strict";

import assert from "assert";
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
});
