# ---------------------------------------------------------------------------
# Python fuzzing environment using Atheris
#
# Atheris is a coverage-guided fuzzer for Python based on libFuzzer.
# It uses native code instrumentation via Python's C API.
#
#   Tool: https://github.com/google/atheris
#
# Supports: pip/pypi ecosystem via requirements.txt
# ---------------------------------------------------------------------------
FROM python:3.11-slim-bookworm

# Install build dependencies for Atheris (requires compilation)
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libclang-14-dev \
        clang-14 \
    && rm -rf /var/lib/apt/lists/*

# Set clang as default compiler for Atheris
ENV CC=clang-14
ENV CXX=clang++-14

WORKDIR /fuzz

# Install Atheris
RUN pip install --no-cache-dir atheris

# Install target libraries at their exact SBOM versions
COPY requirements.txt /fuzz/
RUN pip install --no-cache-dir -r requirements.txt

COPY targets/ /fuzz/targets/
COPY corpus/  /fuzz/corpus/
COPY run.sh   /fuzz/run.sh
COPY tools/   /fuzz/tools/
RUN chmod +x /fuzz/run.sh

# Output (corpus growth + crash files) lands in /fuzz/findings (bind-mount it)
RUN mkdir -p /fuzz/findings

ENTRYPOINT ["/fuzz/run.sh"]
