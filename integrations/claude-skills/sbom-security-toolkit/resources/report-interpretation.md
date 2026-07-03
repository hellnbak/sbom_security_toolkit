# Report Interpretation Guide

## SBOM quality score

A low score usually means the SBOM is difficult to trust operationally. Common causes include missing package URLs, missing versions, no dependency graph, missing licenses, missing hashes, or duplicate components.

## Policy result

A policy failure means the SBOM does not satisfy the configured gate. It is not always proof that the product is vulnerable; it may indicate missing evidence, missing VEX status, or insufficient metadata.

## Scanner disagreement

Common causes include package-url mismatch, CPE fallback, ecosystem ambiguity, distro-specific vulnerability matching, missing versions, or scanner database differences.

## Supplier questions

Supplier questions should be framed as evidence requests, not accusations. Ask for missing dependency graphs, VEX status, component hashes, unsupported component clarification, and scope clarification.

## Fuzzing results

A fuzzing crash or semantic mismatch should be reproduced, minimized, deduplicated, and reviewed before being treated as a reportable vulnerability.
