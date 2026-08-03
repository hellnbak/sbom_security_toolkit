#!/bin/bash -eu

cd "$SRC/sbom_security_toolkit"
pip3 install .

for fuzzer in fuzzing/engines/python/targets/*.py; do
  fuzzer_basename="$(basename -s .py "$fuzzer")"
  fuzzer_package="${fuzzer_basename}.pkg"
  mkdir -p "$WORK/$fuzzer_basename"

  pyinstaller \
    --distpath "$OUT" \
    --workpath "$WORK/$fuzzer_basename" \
    --specpath "$WORK/$fuzzer_basename" \
    --onefile \
    --name "$fuzzer_package" \
    "$fuzzer"

  cat > "$OUT/$fuzzer_basename" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for ClusterFuzzLite fuzzer detection.
this_dir=\$(CDPATH= cd -- "\$(dirname -- "\$0")" && pwd)
export ASAN_OPTIONS="\${ASAN_OPTIONS:-}:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0"
exec "\$this_dir/$fuzzer_package" "\$@"
EOF
  chmod +x "$OUT/$fuzzer_basename"

  seed_dir="fuzzing/engines/python/corpus/$fuzzer_basename"
  if [ -d "$seed_dir" ]; then
    (
      cd "$seed_dir"
      python3 -m zipfile -c "$OUT/${fuzzer_basename}_seed_corpus.zip" ./*
    )
  fi
done
