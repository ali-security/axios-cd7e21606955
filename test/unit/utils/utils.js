import assert from 'assert';
import utils from '../../../lib/utils.js';
import FormData from 'form-data';
import stream from 'stream';

describe('utils', function (){
  it('should validate Stream', function () {
    assert.strictEqual(utils.isStream(new stream.Readable()),true);
    assert.strictEqual(utils.isStream({ foo: 'bar' }),false);
  });

  it('should validate Buffer', function () {
    assert.strictEqual(utils.isBuffer(Buffer.from('a')),true);
    assert.strictEqual(utils.isBuffer(null),false);
    assert.strictEqual(utils.isBuffer(undefined),false);
  });

  describe('utils::isFormData', function () {
    it('should detect the FormData instance provided by the `form-data` package', function () {
      [1, 'str', {}, new RegExp()].forEach(function (thing) {
        assert.equal(utils.isFormData(thing), false);
      });
      assert.equal(utils.isFormData(new FormData()), true);
    });

    it('should not call toString method on built-in objects instances', () => {
      const buf = Buffer.from('123');

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should not call toString method on built-in objects instances, even if append method exists', () => {
      const buf = Buffer.from('123');

      buf.append = () => {};

      buf.toString = () => assert.fail('should not be called');

      assert.equal(utils.isFormData(buf), false);
    });

    it('should detect custom FormData instances by toStringTag signature and append method presence', () => {
      class FormData {
        append(){

        }

        get [Symbol.toStringTag]() {
          return 'FormData';
        }
      }
      assert.equal(utils.isFormData(new FormData()), true);
    });

    it('should not treat plain objects as FormData even if they look like one (GHSA-6chq-wfr3-2hj9)', () => {
      const spoofed = {append() {}, [Symbol.toStringTag]: 'FormData'};
      assert.equal(utils.isFormData(spoofed), false);

      const nullProto = Object.create(null);
      nullProto.append = () => {};
      nullProto[Symbol.toStringTag] = 'FormData';
      assert.equal(utils.isFormData(nullProto), false);

      const legacySpoof = {append() {}, toString() { return '[object FormData]'; }};
      assert.equal(utils.isFormData(legacySpoof), false);
    });

    it('should not treat plain objects as FormData when Object.prototype is polluted (GHSA-6chq-wfr3-2hj9)', () => {
      Object.prototype[Symbol.toStringTag] = 'FormData';
      Object.prototype.append = () => {};

      try {
        assert.equal(utils.isFormData({userId: 42}), false);
      } finally {
        delete Object.prototype[Symbol.toStringTag];
        delete Object.prototype.append;
      }
    });
  });

  describe('toJSON', function (){
    it('should convert to a plain object without circular references', function () {
      const obj= {a: [0]}
      const source = {x:1, y:2, obj};
      source.circular1 = source;
      obj.a[1] = obj;

      assert.deepStrictEqual(utils.toJSONObject(source), {
        x: 1, y:2, obj: {a: [0]}
      });
    });

    it('should use objects with defined toJSON method without rebuilding', function () {
      const objProp = {};
      const obj= {objProp, toJSON(){
        return {ok: 1}
      }};
      const source = {x:1, y:2, obj};

      const jsonObject = utils.toJSONObject(source);

      assert.strictEqual(jsonObject.obj.objProp, objProp);
      assert.strictEqual(JSON.stringify(jsonObject), JSON.stringify({x: 1, y:2, obj: {ok: 1}}))
    });
  });
});
