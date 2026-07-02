# ---------------------------------------------------------------------------
# Fuzzing environment for the SBOM's parser/input-handling libraries.
#
# Uses nikic/PHP-Fuzzer (MIT) — a coverage-guided, libFuzzer-style fuzzer for
# PHP. It instruments included files on the fly (via nikic/php-parser +
# include-interceptor) to get edge-coverage feedback, exactly the technique
# libFuzzer/AFL use for native code, adapted to the PHP interpreter.
#
#   Tool: https://github.com/nikic/PHP-Fuzzer
#
# php-fuzzer is installed as a .phar (upstream-recommended) so its internal
# php-parser dependency does not clash with the php-parser we fuzz as a target.
# ---------------------------------------------------------------------------
FROM php:8.3-cli-bookworm

# pcntl => timeout support (treats hangs as crashes).
# sockets => required by datadog/php-datadogstatsd.
# Build deps for composer.
RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libzip-dev curl ca-certificates \
    && docker-php-ext-install pcntl sockets \
    && rm -rf /var/lib/apt/lists/*

# Composer (multi-stage copy from official image)
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /fuzz

# Install php-fuzzer as a pinned phar.
# Pin the version you validate; "latest" shown here for clarity.
RUN curl -fsSL -o /usr/local/bin/php-fuzzer.phar \
        https://github.com/nikic/PHP-Fuzzer/releases/latest/download/php-fuzzer.phar \
    && printf '#!/bin/sh\nexec php /usr/local/bin/php-fuzzer.phar "$@"\n' > /usr/local/bin/php-fuzzer \
    && chmod +x /usr/local/bin/php-fuzzer

# Install the target libraries at their exact SBOM versions.
COPY composer.json /fuzz/composer.json
RUN composer install --no-interaction --no-progress --prefer-dist

COPY targets/ /fuzz/targets/
COPY corpus/  /fuzz/corpus/
COPY run.sh   /fuzz/run.sh
RUN chmod +x /fuzz/run.sh

# Output (corpus growth + crash files) lands in /fuzz/findings (bind-mount it).
RUN mkdir -p /fuzz/findings

ENTRYPOINT ["/fuzz/run.sh"]
