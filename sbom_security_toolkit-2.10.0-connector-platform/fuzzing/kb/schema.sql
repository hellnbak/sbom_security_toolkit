-- Local SQLite schema for SBOM Security Toolkit fuzzing knowledge base.
CREATE TABLE IF NOT EXISTS campaigns (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  target TEXT,
  started_at TEXT,
  completed_at TEXT,
  status TEXT,
  metadata_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS corpus_entries (
  sha256 TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  format TEXT,
  source TEXT,
  first_seen_at TEXT,
  metadata_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  campaign_id TEXT,
  finding_type TEXT,
  target TEXT,
  severity TEXT,
  input_sha256 TEXT,
  fingerprint TEXT,
  summary TEXT,
  artifact_path TEXT,
  created_at TEXT,
  metadata_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS coverage_snapshots (
  id TEXT PRIMARY KEY,
  campaign_id TEXT,
  target TEXT,
  lines REAL,
  branches REAL,
  new_paths INTEGER DEFAULT 0,
  corpus_size INTEGER DEFAULT 0,
  created_at TEXT,
  metadata_json TEXT DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS ai_suggestions (
  id TEXT PRIMARY KEY,
  provider TEXT,
  suggestion_type TEXT,
  prompt_path TEXT,
  output_path TEXT,
  status TEXT DEFAULT 'pending_review',
  created_at TEXT,
  metadata_json TEXT DEFAULT '{}'
);
