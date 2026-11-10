ALTER TABLE threat_memories
  ADD COLUMN source_inspection_id text REFERENCES direct_inspections(id) ON DELETE CASCADE;

CREATE UNIQUE INDEX threat_memories_inspection_fingerprint
  ON threat_memories (source_inspection_id, safe_fingerprint)
  WHERE source_inspection_id IS NOT NULL;

CREATE INDEX threat_memories_inspection
  ON threat_memories (source_inspection_id)
  WHERE source_inspection_id IS NOT NULL;
