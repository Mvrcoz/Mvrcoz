import test from 'node:test';
import assert from 'node:assert/strict';
import { FEATURES, hasFeature } from '../js/features.js';

test('every v1 feature is free and allowed', () => {
  assert.deepEqual(Object.keys(FEATURES).sort(),
    ['breach-lookup', 'daily-checkup', 'generator', 'link-check', 'password-check']);
  for (const id of Object.keys(FEATURES)) assert.equal(hasFeature(id), true);
});
test('unknown feature is not allowed', () => assert.equal(hasFeature('nope'), false));
test('inherited object keys are not features', () => assert.equal(hasFeature('toString'), false));
