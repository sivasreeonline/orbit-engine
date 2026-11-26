BEGIN;

INSERT INTO problems (
  id, tenant_id, slug, lifecycle_status, current_version_id, sort_order
)
VALUES (
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
  NULL,
  'two-sum',
  'DRAFT',
  NULL,
  100
)
ON CONFLICT DO NOTHING;

INSERT INTO problem_versions (
  id, problem_id, version_number, title, difficulty, category, tags, summary,
  statement, input_format, output_format, constraints, published_at
)
VALUES (
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1',
  1,
  'Two Sum',
  'Easy',
  'Arrays & Hashing',
  ARRAY['Array', 'Hash Map'],
  'Find two distinct indices whose values add up to the target.',
  'Given an integer array and a target value, return the indices of two distinct elements whose sum equals the target. You may assume exactly one valid pair exists. A value cannot be used twice.',
  ARRAY[
    'The first line contains two integers: n and target.',
    'The second line contains n space-separated integers.'
  ],
  'Print the two zero-based indices in ascending order, separated by one space.',
  ARRAY[
    '2 <= n <= 100000',
    '-1000000000 <= nums[i] <= 1000000000',
    '-2000000000 <= target <= 2000000000'
  ],
  NULL
)
ON CONFLICT (problem_id, version_number) DO NOTHING;

INSERT INTO problem_test_cases (
  id, problem_version_id, sequence, input_data, expected_output, explanation, visibility
)
SELECT
  'cccccccc-cccc-4ccc-8ccc-ccccccccccc1',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  1,
  convert_to(E'4 9\n2 7 11 15', 'UTF8'),
  convert_to('0 1', 'UTF8'),
  '2 + 7 = 9, so the answer is indices 0 and 1.',
  'PUBLIC'
WHERE NOT EXISTS (
  SELECT 1 FROM problem_test_cases
  WHERE problem_version_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
    AND sequence = 1
);

INSERT INTO problem_test_cases (
  id, problem_version_id, sequence, input_data, expected_output, explanation, visibility
)
SELECT
  'cccccccc-cccc-4ccc-8ccc-ccccccccccc2',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  2,
  convert_to(E'3 6\n3 2 4', 'UTF8'),
  convert_to('1 2', 'UTF8'),
  '2 + 4 = 6, so the answer is indices 1 and 2.',
  'PUBLIC'
WHERE NOT EXISTS (
  SELECT 1 FROM problem_test_cases
  WHERE problem_version_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
    AND sequence = 2
);

INSERT INTO problem_test_cases (
  id, problem_version_id, sequence, input_data, expected_output, explanation, visibility
)
SELECT
  'cccccccc-cccc-4ccc-8ccc-ccccccccccc3',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  101,
  convert_to(E'5 10\n1 9 3 7 5', 'UTF8'),
  convert_to('0 1', 'UTF8'),
  NULL,
  'HIDDEN'
WHERE NOT EXISTS (
  SELECT 1 FROM problem_test_cases
  WHERE problem_version_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
    AND sequence = 101
);

INSERT INTO problem_test_cases (
  id, problem_version_id, sequence, input_data, expected_output, explanation, visibility
)
SELECT
  'cccccccc-cccc-4ccc-8ccc-ccccccccccc4',
  'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
  102,
  convert_to(E'4 0\n-3 7 3 1', 'UTF8'),
  convert_to('0 2', 'UTF8'),
  NULL,
  'HIDDEN'
WHERE NOT EXISTS (
  SELECT 1 FROM problem_test_cases
  WHERE problem_version_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
    AND sequence = 102
);

UPDATE problem_versions
SET published_at = now()
WHERE id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
  AND published_at IS NULL;

UPDATE problems
SET current_version_id = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1',
    lifecycle_status = 'PUBLISHED',
    updated_at = now()
WHERE id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'
  AND (
    current_version_id IS DISTINCT FROM 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'
    OR lifecycle_status <> 'PUBLISHED'
  );

INSERT INTO schema_migrations (version, description)
VALUES ('0002_seed_two_sum', 'Seed global Two Sum v1 with two public and two hidden fixtures')
ON CONFLICT (version) DO NOTHING;

COMMIT;
