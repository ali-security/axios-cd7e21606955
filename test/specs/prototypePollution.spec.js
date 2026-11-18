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
