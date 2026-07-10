/**
 * Fuzz target: Ajv (JSON Schema validator)
 *
 * JSON Schema validation is a classic attack surface:
 * - ReDoS in pattern validators
 * - Complexity exploits in recursive schemas
 * - Type confusion bugs
 *
 * We fuzz both the schema compilation and the validation phases.
 */

import Ajv from 'ajv';

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
  try {
    const input = data.toString('utf-8');
    if (input.length > 10000) return;

    // Try to parse as JSON (most inputs will fail, that's fine)
    let obj;
    try {
      obj = JSON.parse(input);
    } catch {
      return; // Not JSON, skip
    }

    // If it's an object with a "schema" key, treat it as schema definition
    if (obj && typeof obj === 'object') {
      const ajv = new Ajv({ strict: false });

      if ('schema' in obj && 'data' in obj) {
        // Fuzz case 1: compile schema + validate data
        try {
          const validate = ajv.compile(obj.schema);
          validate(obj.data);
        } catch (e) {
          // Schema compilation errors are expected for invalid schemas
          if (e.message.includes('stack')) throw e;
        }
      } else {
        // Fuzz case 2: just compile the schema itself
        try {
          ajv.compile(obj);
        } catch (e) {
          if (e.message.includes('stack')) throw e;
        }
      }
    }
  } catch (e) {
    // Let real bugs (stack overflow, RangeError, etc.) bubble up
    if (e instanceof RangeError || e.message.includes('stack')) {
      throw e;
    }
  }
}
