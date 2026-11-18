import xhrAdapter from '../../lib/adapters/xhr.js';

// GHSA-q8qp-cvcw-x6jj: config properties such as `auth` and `baseURL` must be
// read as own properties only, so a polluted Object.prototype cannot inject
// credentials or redirect requests to an attacker-controlled host.
describe('prototype pollution gadgets (GHSA-q8qp-cvcw-x6jj)', function () {
  beforeEach(function () {
    jasmine.Ajax.install();
  });

  afterEach(function () {
    delete Object.prototype.auth;
    delete Object.prototype.baseURL;
    jasmine.Ajax.uninstall();
  });

  it('should not pick up Object.prototype.auth as an Authorization header', function (done) {
    Object.prototype.auth = {username: 'attacker', password: 'exfil'};

    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders['Authorization']).toEqual(undefined);
      done();
    });
  });

  it('should not prefix relative URLs with Object.prototype.baseURL', function (done) {
    Object.prototype.baseURL = 'http://evil.example.com';

    axios('/foo');

    getAjaxRequest().then(function (request) {
      expect(request.url).toBe('/foo');
      done();
    });
  });

  it('xhr adapter should only read own auth and baseURL config properties', function (done) {
    Object.prototype.auth = {username: 'attacker', password: 'exfil'};
    Object.prototype.baseURL = 'http://evil.example.com';

    xhrAdapter({url: '/foo', method: 'get', headers: {}}).catch(function () {});

    getAjaxRequest().then(function (request) {
      expect(request.url).toBe('/foo');
      expect(request.requestHeaders['Authorization']).toEqual(undefined);
      done();
    });
  });
});

// GHSA-7q8q-rj6j-mhjq (CVE-2026-67319): fields of nested option objects such as
// `auth: {}` and `paramsSerializer: {}` must not be inherited from a polluted
// Object.prototype (Basic auth header injection, query-string tampering).
describe('nested option object pollution gadgets (GHSA-7q8q-rj6j-mhjq)', function () {
  const pollutedKeys = ['username', 'password', 'serialize', 'encode'];

  function pollute(key, value) {
    Object.defineProperty(Object.prototype, key, {
      value: value,
      configurable: true,
      writable: true
    });
  }

  beforeEach(function () {
    jasmine.Ajax.install();
  });

  afterEach(function () {
    pollutedKeys.forEach(function (key) {
      delete Object.prototype[key];
    });
    jasmine.Ajax.uninstall();
  });

  it('should not build Basic auth from inherited username/password on an empty auth object', function (done) {
    pollute('username', 'attacker');
    pollute('password', 'exfil');

    axios('/foo', {auth: {}});

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders['Authorization']).toEqual('Basic Og==');
      done();
    });
  });

  it('should still send own auth credentials when Object.prototype is polluted', function (done) {
    pollute('username', 'attacker');
    pollute('password', 'exfil');

    axios('/foo', {auth: {username: 'Aladdin', password: 'open sesame'}});

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders['Authorization']).toEqual('Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==');
      done();
    });
  });

  it('should not let inherited serialize/encode tamper with the query string', function (done) {
    let invoked = false;

    pollute('serialize', function () {
      invoked = true;
      return 'polluted=1';
    });
    pollute('encode', function () {
      invoked = true;
      return 'polluted';
    });

    axios('/foo', {params: {value: 'a b'}, paramsSerializer: {}});

    getAjaxRequest().then(function (request) {
      expect(request.url).toBe('/foo?value=a+b');
      expect(invoked).toBe(false);
      done();
    });
  });

  it('xhr adapter should ignore inherited nested auth fields', function (done) {
    pollute('username', 'attacker');
    pollute('password', 'exfil');

    xhrAdapter({url: '/foo', method: 'get', headers: {}, auth: {}}).catch(function () {});

    getAjaxRequest().then(function (request) {
      expect(request.requestHeaders['Authorization']).toEqual('Basic Og==');
      done();
    });
  });
});
