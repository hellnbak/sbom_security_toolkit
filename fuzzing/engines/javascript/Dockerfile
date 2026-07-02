# ---------------------------------------------------------------------------
# JavaScript/TypeScript fuzzing environment using Jazzer.js
#
# Jazzer.js is a coverage-guided fuzzer for Node.js based on libFuzzer.
# It uses V8's built-in coverage instrumentation for feedback.
#
#   Tool: https://github.com/CodeIntelligenceTesting/jazzer.js
#
# Supports: npm, yarn, pnpm ecosystems via package.json
# ---------------------------------------------------------------------------
FROM node:20-bookworm-slim

WORKDIR /fuzz

# Install target libraries at their exact SBOM versions
COPY package.json package-lock.json* /fuzz/
RUN npm install

# TypeScript support (if targets use .ts files)
RUN npm install --save-dev typescript ts-node @types/node

COPY targets/ /fuzz/targets/
COPY corpus/  /fuzz/corpus/
COPY run.sh   /fuzz/run.sh
RUN chmod +x /fuzz/run.sh

# Output (corpus growth + crash files) lands in /fuzz/findings (bind-mount it)
RUN mkdir -p /fuzz/findings

ENTRYPOINT ["/fuzz/run.sh"]
