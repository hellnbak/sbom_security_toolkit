/**
 * Fuzz target: semver (semantic version parser)
 *
 * Version string parsing is attacker-reachable in many contexts:
 * - Package managers
 * - Dependency resolution
 * - API version negotiation
 *
 * Prime target for ReDoS and parsing bugs.
 */

import semver from 'semver';

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
  try {
    const input = data.toString('utf-8');

    // Bound input length
    if (input.length > 500) return;

    // Try various semver operations
    const parsed = semver.parse(input);

    if (parsed) {
      // Exercise comparison logic
      semver.valid(input);
      semver.clean(input);

      // Range parsing (different code path)
      const range = semver.validRange(input);
      if (range) {
        // Exercise range matching
        semver.satisfies(parsed.version, range);
      }
    }
  } catch (e) {
    // Expected parse errors are fine
    // RangeError, stack overflow are bugs
    if (e instanceof RangeError || e.message.includes('stack')) {
      throw e;
    }
  }
}
