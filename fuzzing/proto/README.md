# Structured Fuzzing Model

`sbom_fuzz_model.proto` is a future libprotobuf-mutator-compatible model for generating SBOM-like structures and rendering them as CycloneDX JSON, CycloneDX XML, SPDX JSON, or SPDX tag-value.

This repo keeps the proto as a scaffold so teams can add native libFuzzer/libprotobuf-mutator targets without changing the higher-level campaign workflow.
