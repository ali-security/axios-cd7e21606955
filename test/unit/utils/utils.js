import assert from 'assert';
import utils from '../../../lib/utils.js';
import FormData from 'form-data';
import stream from 'stream';
import vm from 'vm';

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

  describe('utils::toSafeFlatObject / prototype boundaries', function () {
    it('should ignore members inherited only from a foreign realm Object.prototype', function () {
      const foreign = vm.runInNewContext(
        "Object.prototype.username = 'attacker'; Object.prototype.serialize = () => 'polluted=1'; ({})"
      );

      // sanity: the cross-realm pollution primitive is active for plain dotted reads
      assert.strictEqual(foreign.username, 'attacker');

      assert.strictEqual(utils.hasOwnInPrototypeChain(foreign, 'username'), false);
      assert.strictEqual(utils.getSafeProp(foreign, 'username'), undefined);
      assert.strictEqual(utils.getSafeProp(foreign, 'serialize'), undefined);
      assert.strictEqual(utils.toSafeFlatObject(foreign).username, undefined);
    });

    it('should stop safe prototype flattening on cyclic Proxy prototypes', function () {
      let calls = 0;
      const proxy = new Proxy({}, {
        getPrototypeOf() {
          calls += 1;
          if (calls > 1) {
            throw new Error('cycled');
          }
          return proxy;
        }
      });

      assert.deepStrictEqual(Object.keys(utils.toSafeFlatObject(proxy)), []);
      assert.strictEqual(calls, 1);
    });

    it('should preserve null-prototype sources but exclude terminal templates', function () {
      const root = Object.create(null);
      root.own = 'preserved';

      assert.strictEqual(utils.getSafeProp(root, 'own'), 'preserved');
      assert.strictEqual(utils.toSafeFlatObject(root), root);

      const template = Object.create(null);
      template.inherited = 'excluded';

      const source = Object.create(template);
      source.own = 'preserved';

      assert.strictEqual(utils.getSafeProp(source, 'own'), 'preserved');
      assert.strictEqual(utils.getSafeProp(source, 'inherited'), undefined);

      const flattened = utils.toSafeFlatObject(source);

      assert.strictEqual(flattened.own, 'preserved');
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'inherited'), false);
    });

    it('should materialize immutable null-prototype sources', function () {
      const source = Object.freeze(Object.assign(Object.create(null), { own: 'preserved' }));
      const flattened = utils.toSafeFlatObject(source);

      assert.notStrictEqual(flattened, source);
      assert.strictEqual(Object.getPrototypeOf(flattened), null);
      assert.strictEqual(flattened.own, 'preserved');
      assert.strictEqual(Object.isFrozen(flattened), false);
    });

    it('should materialize and filter unsafe keys from null-prototype sources', function () {
      const source = Object.create(null);
      source.safe = 'preserved';
      Object.defineProperty(source, '__proto__', {
        value: 'excluded',
        enumerable: true,
        configurable: true,
        writable: true
      });
      source.constructor = 'excluded';
      source.prototype = 'excluded';

      const flattened = utils.toSafeFlatObject(source);

      assert.notStrictEqual(flattened, source);
      assert.strictEqual(flattened.safe, 'preserved');
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, '__proto__'), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'prototype'), false);
    });

    it('should exclude symbols inherited from terminal null-prototype templates', function () {
      const behavior = Symbol('behavior');
      const template = Object.create(null);
      template[behavior] = () => 'excluded';

      const source = Object.create(template);
      const flattened = utils.toSafeFlatObject(source);

      assert.strictEqual(utils.getSafeProp(source, behavior), undefined);
      assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, behavior), false);
    });

    it('should flatten class and template members but not Object.prototype members', function () {
      Object.prototype.pollutedFlatKey = 'polluted';

      try {
        class Template {
          method() {
            return 'class';
          }
        }

        const source = new Template();
        source.own = 'preserved';

        const flattened = utils.toSafeFlatObject(source);

        assert.strictEqual(Object.getPrototypeOf(flattened), null);
        assert.strictEqual(flattened.own, 'preserved');
        assert.strictEqual(flattened.method(), 'class');
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'constructor'), false);
        assert.strictEqual(Object.prototype.hasOwnProperty.call(flattened, 'pollutedFlatKey'), false);
        assert.strictEqual(flattened.pollutedFlatKey, undefined);
      } finally {
        delete Object.prototype.pollutedFlatKey;
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
