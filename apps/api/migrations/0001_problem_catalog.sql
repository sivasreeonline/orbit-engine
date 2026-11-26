BEGIN;

CREATE TABLE IF NOT EXISTS schema_migrations (
  version varchar(80) PRIMARY KEY,
  description text NOT NULL,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS problems (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tenant_id uuid NULL,
  slug varchar(64) NOT NULL,
  lifecycle_status varchar(16) NOT NULL DEFAULT 'DRAFT'
    CHECK (lifecycle_status IN ('DRAFT', 'PUBLISHED', 'ARCHIVED')),
  current_version_id uuid NULL,
  sort_order integer NOT NULL DEFAULT 1000,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_problems_global_slug
  ON problems (slug)
  WHERE tenant_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_problems_tenant_slug
  ON problems (tenant_id, slug)
  WHERE tenant_id IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_problems_published_order
  ON problems (tenant_id, sort_order, slug)
  WHERE lifecycle_status = 'PUBLISHED';

CREATE TABLE IF NOT EXISTS problem_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  problem_id uuid NOT NULL REFERENCES problems(id) ON DELETE RESTRICT,
  version_number integer NOT NULL CHECK (version_number > 0),
  title varchar(160) NOT NULL,
  difficulty varchar(16) NOT NULL
    CHECK (difficulty IN ('Easy', 'Medium', 'Hard')),
  category varchar(100) NOT NULL,
  tags text[] NOT NULL DEFAULT '{}',
  summary varchar(500) NOT NULL,
  statement text NOT NULL,
  input_format text[] NOT NULL DEFAULT '{}',
  output_format text NOT NULL,
  constraints text[] NOT NULL DEFAULT '{}',
  published_at timestamptz NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (problem_id, version_number),
  UNIQUE (id, problem_id)
);

CREATE INDEX IF NOT EXISTS idx_problem_versions_published
  ON problem_versions (problem_id, version_number DESC)
  WHERE published_at IS NOT NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'problems_current_version_fk'
      AND conrelid = 'problems'::regclass
  ) THEN
    ALTER TABLE problems
      ADD CONSTRAINT problems_current_version_fk
      FOREIGN KEY (current_version_id, id)
      REFERENCES problem_versions (id, problem_id)
      ON DELETE RESTRICT
      DEFERRABLE INITIALLY DEFERRED;
  END IF;
END
$$;

CREATE TABLE IF NOT EXISTS problem_test_cases (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  problem_version_id uuid NOT NULL
    REFERENCES problem_versions(id) ON DELETE RESTRICT,
  sequence integer NOT NULL CHECK (sequence > 0),
  input_data bytea NOT NULL,
  expected_output bytea NOT NULL,
  explanation text NULL,
  visibility varchar(12) NOT NULL
    CHECK (visibility IN ('PUBLIC', 'HIDDEN')),
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (problem_version_id, sequence),
  CHECK (visibility = 'PUBLIC' OR explanation IS NULL)
);

CREATE INDEX IF NOT EXISTS idx_problem_test_cases_public_order
  ON problem_test_cases (problem_version_id, sequence)
  WHERE visibility = 'PUBLIC';

CREATE OR REPLACE VIEW public_problem_test_cases
WITH (security_barrier = true)
AS
SELECT problem_version_id, sequence, input_data, expected_output, explanation
FROM problem_test_cases
WHERE visibility = 'PUBLIC';

COMMENT ON VIEW public_problem_test_cases IS
  'Student/API-safe test fixtures only. Hidden test cases are excluded by the view predicate.';

CREATE OR REPLACE FUNCTION prevent_published_problem_version_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.published_at IS NOT NULL THEN
    RAISE EXCEPTION 'published problem versions are immutable'
      USING ERRCODE = '55000';
  END IF;
  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_problem_versions_immutable ON problem_versions;
CREATE TRIGGER trg_problem_versions_immutable
BEFORE UPDATE OR DELETE ON problem_versions
FOR EACH ROW
EXECUTE FUNCTION prevent_published_problem_version_mutation();

CREATE OR REPLACE FUNCTION prevent_published_test_case_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP IN ('UPDATE', 'DELETE') AND EXISTS (
    SELECT 1 FROM problem_versions
    WHERE id = OLD.problem_version_id AND published_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'test cases for published problem versions are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP IN ('INSERT', 'UPDATE') AND EXISTS (
    SELECT 1 FROM problem_versions
    WHERE id = NEW.problem_version_id AND published_at IS NOT NULL
  ) THEN
    RAISE EXCEPTION 'test cases for published problem versions are immutable'
      USING ERRCODE = '55000';
  END IF;

  IF TG_OP = 'DELETE' THEN
    RETURN OLD;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_problem_test_cases_immutable ON problem_test_cases;
CREATE TRIGGER trg_problem_test_cases_immutable
BEFORE INSERT OR UPDATE OR DELETE ON problem_test_cases
FOR EACH ROW
EXECUTE FUNCTION prevent_published_test_case_mutation();

INSERT INTO schema_migrations (version, description)
VALUES ('0001_problem_catalog', 'Problem catalog, immutable versions and public-only test view')
ON CONFLICT (version) DO NOTHING;

COMMIT;
