/**
 * Fuzz target: marked (Markdown parser)
 *
 * Markdown parsers are prime fuzzing targets - complex grammar, attacker-controlled
 * input in comments/user content, history of XSS and DoS bugs.
 *
 * This follows the Jazzer.js pattern: export a fuzz function that takes Buffer.
 */

import { marked } from 'marked';

/**
 * @param { Buffer } data
 */
export function fuzz(data) {
  try {
    const input = data.toString('utf-8');

    // Bound the input length to avoid trivial OOM
    if (input.length > 100000) return;

    // Parse markdown to HTML
    const html = marked.parse(input);

    // Force evaluation of result (don't let V8 optimize away)
    if (html.includes('\x00')) {
      throw new Error('Null byte in output');
    }
  } catch (e) {
    // Expected exceptions for invalid input are fine
    // Only uncaught exceptions trigger crashes
    if (e.message.includes('Maximum call stack')) {
      throw e; // Stack overflow is a real bug
    }
  }
}
