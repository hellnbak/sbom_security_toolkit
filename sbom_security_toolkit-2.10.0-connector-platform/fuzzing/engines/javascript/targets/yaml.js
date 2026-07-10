/**
 * Fuzz target: js-yaml (YAML parser)
 *
 * YAML parsers have a rich history of security bugs:
 * - Billion laughs (alias expansion)
 * - Stack overflow on deep nesting
 * - Type confusion with !!js/* tags
 * - ReDoS in various patterns
 */

import yaml from 'js-yaml';

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
  try {
    const input = data.toString('utf-8');

    // Bound input to avoid trivial resource exhaustion
    if (input.length > 50000) return;

    // Parse YAML with safe schema (no code execution)
    const parsed = yaml.load(input, {
      schema: yaml.SAFE_SCHEMA,
      json: false,
    });

    // Force evaluation
    if (parsed && typeof parsed === 'object') {
      JSON.stringify(parsed); // Will throw on circular refs
    }
  } catch (e) {
    // Expected YAML syntax errors are fine
    // Stack overflows and RangeErrors are real bugs
    if (
      e instanceof RangeError ||
      e.message.includes('stack') ||
      e.message.includes('Maximum call stack')
    ) {
      throw e;
    }
  }
}
