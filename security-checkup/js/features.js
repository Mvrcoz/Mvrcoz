// The one place the app asks "is this allowed?".
// Version 1: every feature is free. A paid tier later changes this module only.

export const FEATURES = Object.freeze({
  'password-check': 'free',
  'breach-lookup': 'free',
  'link-check': 'free',
  'generator': 'free',
  'daily-checkup': 'free',
});

export function hasFeature(id) {
  return Object.hasOwn(FEATURES, id) && FEATURES[id] === 'free';
}
