BEGIN;

-- The editor may legitimately capture an empty starter document.
ALTER TABLE source_snapshots
  DROP CONSTRAINT IF EXISTS source_snapshots_byte_length_check;
ALTER TABLE source_snapshots
  ADD CONSTRAINT source_snapshots_byte_length_nonnegative
  CHECK (byte_length >= 0);

CREATE TABLE IF NOT EXISTS coding_evidence_sessions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NOT NULL,
  actor_user_id uuid NOT NULL,
  problem_id uuid NOT NULL,
  problem_version_id uuid NOT NULL,
  language varchar(16) NOT NULL CHECK (language IN ('java', 'python')),
  notice_version varchar(32) NOT NULL
    CHECK (length(notice_version) BETWEEN 1 AND 32),
  status varchar(12) NOT NULL DEFAULT 'ACTIVE'
    CHECK (status IN ('ACTIVE', 'ENDED')),
  last_sequence bigint NOT NULL DEFAULT 0 CHECK (last_sequence >= 0),
  started_at timestamptz NOT NULL DEFAULT now(),
  last_received_at timestamptz NOT NULL DEFAULT now(),
  ended_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT coding_evidence_session_problem_version_fk
    FOREIGN KEY (problem_version_id, problem_id)
    REFERENCES problem_versions(id, problem_id) ON DELETE RESTRICT,
  CONSTRAINT coding_evidence_session_status_time_ck CHECK (
    (status = 'ACTIVE' AND ended_at IS NULL)
    OR (status = 'ENDED' AND ended_at IS NOT NULL)
  ),
  CONSTRAINT coding_evidence_session_identity_unique
    UNIQUE (id, tenant_id, actor_user_id)
);

CREATE INDEX IF NOT EXISTS idx_coding_evidence_sessions_owner_started
  ON coding_evidence_sessions (tenant_id, actor_user_id, started_at DESC);

CREATE TABLE IF NOT EXISTS editor_code_snapshots (
  id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES coding_evidence_sessions(id) ON DELETE RESTRICT,
  source_snapshot_id uuid NOT NULL UNIQUE
    REFERENCES source_snapshots(id) ON DELETE RESTRICT,
  sequence bigint NOT NULL CHECK (sequence > 0),
  snapshot_kind varchar(16) NOT NULL
    CHECK (snapshot_kind IN (
      'SESSION_START', 'PERIODIC', 'CONTEXT_CHANGE',
      'RUN', 'SUBMIT', 'SESSION_END'
    )),
  language varchar(16) NOT NULL CHECK (language IN ('java', 'python')),
  captured_at timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (session_id, sequence),
  UNIQUE (id, session_id)
);

CREATE INDEX IF NOT EXISTS idx_editor_code_snapshots_session_sequence
  ON editor_code_snapshots (session_id, sequence DESC);

CREATE TABLE IF NOT EXISTS coding_evidence_events (
  event_id uuid PRIMARY KEY,
  session_id uuid NOT NULL REFERENCES coding_evidence_sessions(id) ON DELETE RESTRICT,
  sequence bigint NOT NULL CHECK (sequence > 0),
  event_type varchar(32) NOT NULL
    CHECK (event_type IN (
      'SESSION_STARTED', 'CODE_SNAPSHOT_CREATED', 'CHECKPOINT_RECORDED',
      'EDITOR_CONTEXT_CHANGED', 'RUN_REQUESTED', 'SUBMIT_REQUESTED',
      'SESSION_ENDED'
    )),
  client_occurred_at timestamptz NOT NULL,
  language varchar(16) NOT NULL CHECK (language IN ('java', 'python')),
  snapshot_id uuid NULL,
  payload_sha256 char(64) NOT NULL
    CHECK (payload_sha256 ~ '^[0-9a-f]{64}$'),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb
    CHECK (jsonb_typeof(metadata) = 'object'),
  sequence_gap_before boolean NOT NULL DEFAULT false,
  received_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (session_id, sequence),
  CONSTRAINT coding_evidence_event_snapshot_fk
    FOREIGN KEY (snapshot_id, session_id)
    REFERENCES editor_code_snapshots(id, session_id) ON DELETE RESTRICT,
  CONSTRAINT coding_evidence_event_snapshot_required_ck CHECK (
    event_type NOT IN (
      'CODE_SNAPSHOT_CREATED', 'EDITOR_CONTEXT_CHANGED',
      'RUN_REQUESTED', 'SUBMIT_REQUESTED'
    ) OR snapshot_id IS NOT NULL
  )
);

CREATE INDEX IF NOT EXISTS idx_coding_evidence_events_session_sequence
  ON coding_evidence_events (session_id, sequence);

CREATE INDEX IF NOT EXISTS idx_coding_evidence_events_session_received
  ON coding_evidence_events (session_id, received_at DESC);

CREATE OR REPLACE FUNCTION verify_coding_evidence_session_problem()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  problem_tenant_id uuid;
  problem_status varchar(16);
  version_published_at timestamptz;
BEGIN
  SELECT problem.tenant_id, problem.lifecycle_status, version.published_at
  INTO problem_tenant_id, problem_status, version_published_at
  FROM problems AS problem
  INNER JOIN problem_versions AS version
    ON version.id = NEW.problem_version_id
   AND version.problem_id = problem.id
  WHERE problem.id = NEW.problem_id;

  IF NOT FOUND
    OR problem_status IS DISTINCT FROM 'PUBLISHED'
    OR version_published_at IS NULL
    OR (problem_tenant_id IS NOT NULL AND problem_tenant_id IS DISTINCT FROM NEW.tenant_id) THEN
    RAISE EXCEPTION 'coding evidence session problem/version is not published or authorized'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_coding_evidence_session_problem ON coding_evidence_sessions;
CREATE TRIGGER trg_coding_evidence_session_problem
BEFORE INSERT ON coding_evidence_sessions
FOR EACH ROW EXECUTE FUNCTION verify_coding_evidence_session_problem();

CREATE OR REPLACE FUNCTION verify_editor_code_snapshot_identity()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  session_tenant_id uuid;
  session_actor_user_id uuid;
  session_status varchar(12);
  snapshot_tenant_id uuid;
  snapshot_actor_user_id uuid;
  snapshot_sha256 char(64);
  snapshot_byte_length bigint;
  snapshot_storage_kind varchar(8);
BEGIN
  SELECT tenant_id, actor_user_id, status
  INTO session_tenant_id, session_actor_user_id, session_status
  FROM coding_evidence_sessions
  WHERE id = NEW.session_id;

  SELECT tenant_id, actor_user_id, sha256, byte_length, storage_kind
  INTO snapshot_tenant_id, snapshot_actor_user_id, snapshot_sha256,
       snapshot_byte_length, snapshot_storage_kind
  FROM source_snapshots
  WHERE id = NEW.source_snapshot_id;

  IF session_status IS DISTINCT FROM 'ACTIVE'
    OR session_tenant_id IS DISTINCT FROM snapshot_tenant_id
    OR session_actor_user_id IS DISTINCT FROM snapshot_actor_user_id
    OR snapshot_storage_kind IS DISTINCT FROM 'DATABASE'
    OR snapshot_sha256 IS NULL
    OR snapshot_byte_length < 0 THEN
    RAISE EXCEPTION 'editor snapshot owner, storage or session status is invalid'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_editor_code_snapshot_identity ON editor_code_snapshots;
CREATE TRIGGER trg_editor_code_snapshot_identity
BEFORE INSERT ON editor_code_snapshots
FOR EACH ROW EXECUTE FUNCTION verify_editor_code_snapshot_identity();

CREATE OR REPLACE FUNCTION verify_coding_evidence_event_snapshot()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
DECLARE
  snapshot_sequence bigint;
  snapshot_language varchar(16);
BEGIN
  IF NEW.snapshot_id IS NULL THEN
    RETURN NEW;
  END IF;

  SELECT sequence, language
  INTO snapshot_sequence, snapshot_language
  FROM editor_code_snapshots
  WHERE id = NEW.snapshot_id AND session_id = NEW.session_id;

  IF NOT FOUND
    OR snapshot_sequence > NEW.sequence
    OR snapshot_language IS DISTINCT FROM NEW.language
    OR (NEW.event_type = 'CODE_SNAPSHOT_CREATED' AND snapshot_sequence <> NEW.sequence) THEN
    RAISE EXCEPTION 'coding evidence event snapshot reference is invalid'
      USING ERRCODE = '23514';
  END IF;

  RETURN NEW;
END;
$function$;

DROP TRIGGER IF EXISTS trg_coding_evidence_event_snapshot ON coding_evidence_events;
CREATE TRIGGER trg_coding_evidence_event_snapshot
BEFORE INSERT ON coding_evidence_events
FOR EACH ROW EXECUTE FUNCTION verify_coding_evidence_event_snapshot();

CREATE OR REPLACE FUNCTION prevent_coding_evidence_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $function$
BEGIN
  RAISE EXCEPTION 'coding evidence events and snapshots are append-only'
    USING ERRCODE = '55000';
END;
$function$;

DROP TRIGGER IF EXISTS trg_coding_evidence_events_append_only ON coding_evidence_events;
CREATE TRIGGER trg_coding_evidence_events_append_only
BEFORE UPDATE OR DELETE ON coding_evidence_events
FOR EACH ROW EXECUTE FUNCTION prevent_coding_evidence_mutation();

DROP TRIGGER IF EXISTS trg_editor_code_snapshots_append_only ON editor_code_snapshots;
CREATE TRIGGER trg_editor_code_snapshots_append_only
BEFORE UPDATE OR DELETE ON editor_code_snapshots
FOR EACH ROW EXECUTE FUNCTION prevent_coding_evidence_mutation();

INSERT INTO schema_migrations (version, description)
VALUES (
  '0009_continuous_editor_evidence',
  'Owner-scoped coding sessions, append-only editor events and versioned source snapshots'
)
ON CONFLICT (version) DO NOTHING;

COMMIT;
