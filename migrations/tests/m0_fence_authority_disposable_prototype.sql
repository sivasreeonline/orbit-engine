\set ON_ERROR_STOP on

-- Disposable PostgreSQL prototype only. This script creates and drops its own
-- isolated schema. It is not a production migration or external witness.
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS dblink;
DROP SCHEMA IF EXISTS m0_fence_authority_it CASCADE;
CREATE SCHEMA m0_fence_authority_it;

CREATE TABLE m0_fence_authority_it.host_authority (
    host_id text PRIMARY KEY,
    epoch bigint NOT NULL CHECK (epoch >= 0),
    provider_instance_id text NOT NULL,
    record_version bigint NOT NULL CHECK (record_version > 0),
    pending_operation_id text,
    authority_status text NOT NULL DEFAULT 'ACTIVE'
        CHECK (authority_status IN ('ACTIVE', 'REVOKED', 'QUARANTINED'))
);

CREATE TABLE m0_fence_authority_it.issuances (
    host_id text NOT NULL REFERENCES m0_fence_authority_it.host_authority(host_id),
    operation_id text NOT NULL,
    nonce_digest text NOT NULL,
    request_digest text NOT NULL,
    response_bytes bytea NOT NULL,
    response_digest text NOT NULL,
    issued_epoch bigint NOT NULL,
    target_instance_id text NOT NULL,
    PRIMARY KEY (host_id, operation_id),
    UNIQUE (host_id, nonce_digest),
    UNIQUE (host_id, issued_epoch)
);

CREATE TABLE m0_fence_authority_it.nonce_index (
    host_id text NOT NULL,
    nonce_digest text NOT NULL,
    operation_id text NOT NULL,
    request_digest text NOT NULL,
    response_digest text NOT NULL,
    PRIMARY KEY (host_id, nonce_digest),
    FOREIGN KEY (host_id, operation_id)
        REFERENCES m0_fence_authority_it.issuances(host_id, operation_id)
);

CREATE TABLE m0_fence_authority_it.operation_index (
    host_id text NOT NULL,
    operation_id text NOT NULL,
    nonce_digest text NOT NULL,
    request_digest text NOT NULL,
    response_digest text NOT NULL,
    PRIMARY KEY (host_id, operation_id),
    FOREIGN KEY (host_id, operation_id)
        REFERENCES m0_fence_authority_it.issuances(host_id, operation_id)
);

CREATE TABLE m0_fence_authority_it.checkpoint_intents (
    host_id text NOT NULL,
    generation bigint NOT NULL,
    operation_id text NOT NULL,
    previous_checkpoint_digest text NOT NULL,
    authority_state_digest text NOT NULL,
    response_digest text NOT NULL,
    PRIMARY KEY (host_id, generation),
    UNIQUE (host_id, operation_id),
    FOREIGN KEY (host_id, operation_id)
        REFERENCES m0_fence_authority_it.issuances(host_id, operation_id)
);

-- This table is intentionally a same-database TEST DOUBLE. It is not an
-- independent witness and must never be described as anti-rollback proof.
CREATE TABLE m0_fence_authority_it.acceptance_events (
    host_id text NOT NULL,
    operation_id text NOT NULL,
    target_instance_id text NOT NULL,
    accepted_epoch bigint NOT NULL,
    response_digest text NOT NULL,
    PRIMARY KEY (host_id, operation_id),
    FOREIGN KEY (host_id, operation_id)
        REFERENCES m0_fence_authority_it.issuances(host_id, operation_id)
);

CREATE TABLE m0_fence_authority_it.revocation_events (
    host_id text NOT NULL REFERENCES m0_fence_authority_it.host_authority(host_id),
    revocation_id text NOT NULL,
    reason text NOT NULL,
    PRIMARY KEY (host_id, revocation_id)
);

CREATE TABLE m0_fence_authority_it.simulated_witness_receipts (
    host_id text NOT NULL,
    generation bigint NOT NULL,
    operation_id text NOT NULL,
    authority_state_digest text NOT NULL,
    PRIMARY KEY (host_id, generation),
    UNIQUE (host_id, operation_id)
);

CREATE FUNCTION m0_fence_authority_it.reject_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'immutable authority evidence cannot be updated or deleted'
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER issuance_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.issuances
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER nonce_index_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.nonce_index
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER operation_index_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.operation_index
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER checkpoint_intent_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.checkpoint_intents
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER acceptance_event_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.acceptance_events
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER revocation_event_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.revocation_events
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE FUNCTION m0_fence_authority_it.compute_authority_state_digest(
    p_host_id text
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    state_value jsonb;
BEGIN
    SELECT jsonb_build_object(
        'host_id', authority.host_id,
        'epoch', authority.epoch,
        'provider_instance_id', authority.provider_instance_id,
        'record_version', authority.record_version,
        'pending_operation_id', authority.pending_operation_id,
        'authority_status', authority.authority_status,
        'issuances', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'operation_id', issuance.operation_id,
                'nonce_digest', issuance.nonce_digest,
                'request_digest', issuance.request_digest,
                'response_bytes_hex', encode(issuance.response_bytes, 'hex'),
                'response_digest', issuance.response_digest,
                'issued_epoch', issuance.issued_epoch,
                'target_instance_id', issuance.target_instance_id
            ) ORDER BY issuance.operation_id)
            FROM m0_fence_authority_it.issuances issuance
            WHERE issuance.host_id = authority.host_id
        ), '[]'::jsonb),
        'nonce_index', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'nonce_digest', idx.nonce_digest,
                'operation_id', idx.operation_id,
                'request_digest', idx.request_digest,
                'response_digest', idx.response_digest
            ) ORDER BY idx.nonce_digest)
            FROM m0_fence_authority_it.nonce_index idx
            WHERE idx.host_id = authority.host_id
        ), '[]'::jsonb),
        'operation_index', COALESCE((
            SELECT jsonb_agg(jsonb_build_object(
                'operation_id', idx.operation_id,
                'nonce_digest', idx.nonce_digest,
                'request_digest', idx.request_digest,
                'response_digest', idx.response_digest
            ) ORDER BY idx.operation_id)
            FROM m0_fence_authority_it.operation_index idx
            WHERE idx.host_id = authority.host_id
        ), '[]'::jsonb)
    )
      INTO state_value
      FROM m0_fence_authority_it.host_authority authority
     WHERE authority.host_id = p_host_id;

    IF state_value IS NULL THEN
        RAISE EXCEPTION 'authority aggregate missing' USING ERRCODE = '23503';
    END IF;
    RETURN encode(digest(convert_to(state_value::text, 'UTF8'), 'sha256'), 'hex');
END;
$$;

CREATE FUNCTION m0_fence_authority_it.issue(
    p_host_id text,
    p_operation_id text,
    p_nonce_digest text,
    p_request_digest text,
    p_expected_version bigint,
    p_target_instance_id text
) RETURNS bytea LANGUAGE plpgsql AS $$
DECLARE
    authority_row m0_fence_authority_it.host_authority%ROWTYPE;
    operation_row m0_fence_authority_it.issuances%ROWTYPE;
    nonce_row m0_fence_authority_it.issuances%ROWTYPE;
    response_value bytea;
    response_hash text;
    next_epoch bigint;
    next_generation bigint;
    prior_checkpoint_digest text;
    state_hash text;
BEGIN
    SELECT * INTO authority_row
      FROM m0_fence_authority_it.host_authority
     WHERE host_id = p_host_id
     FOR UPDATE;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown enrolled host' USING ERRCODE = '23503';
    END IF;

    SELECT * INTO operation_row
      FROM m0_fence_authority_it.issuances
     WHERE host_id = p_host_id AND operation_id = p_operation_id;

    SELECT * INTO nonce_row
      FROM m0_fence_authority_it.issuances
     WHERE host_id = p_host_id AND nonce_digest = p_nonce_digest;

    IF operation_row.operation_id IS NOT NULL OR nonce_row.operation_id IS NOT NULL THEN
        IF operation_row.operation_id IS NULL
           OR nonce_row.operation_id IS NULL
           OR operation_row.operation_id <> nonce_row.operation_id
           OR operation_row.request_digest <> p_request_digest
           OR nonce_row.request_digest <> p_request_digest THEN
            RAISE EXCEPTION 'nonce/operation identity or request digest conflict'
                USING ERRCODE = '23505';
        END IF;
        RETURN operation_row.response_bytes;
    END IF;

    IF authority_row.authority_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'authority is not active'
            USING ERRCODE = '55000';
    END IF;

    IF authority_row.record_version <> p_expected_version THEN
        RAISE EXCEPTION 'authority record compare-and-swap conflict'
            USING ERRCODE = '40001';
    END IF;

    IF authority_row.pending_operation_id IS NOT NULL THEN
        RAISE EXCEPTION 'one successor is already pending'
            USING ERRCODE = '55000';
    END IF;

    IF p_target_instance_id = authority_row.provider_instance_id THEN
        RAISE EXCEPTION 'successor must target a distinct provider instance'
            USING ERRCODE = '22023';
    END IF;


    IF EXISTS (
        SELECT 1
          FROM m0_fence_authority_it.acceptance_checkpoint_intents intent
         WHERE intent.host_id = p_host_id
           AND intent.generation = (
               SELECT MAX(generation)
                 FROM m0_fence_authority_it.acceptance_checkpoint_intents
                WHERE host_id = p_host_id
           )
           AND NOT EXISTS (
               SELECT 1
                 FROM m0_fence_authority_it.acceptance_checkpoint_receipts receipt
                WHERE receipt.host_id = intent.host_id
                  AND receipt.generation = intent.generation
                  AND receipt.operation_id = intent.operation_id
                  AND receipt.checkpoint_digest = intent.checkpoint_digest
           )
    ) THEN
        RAISE EXCEPTION 'latest acceptance checkpoint is not acknowledged'
            USING ERRCODE = '55000';
    END IF;

    next_epoch := authority_row.epoch + 1;
    response_value := convert_to(
        jsonb_build_object(
            'host_id', p_host_id,
            'operation_id', p_operation_id,
            'nonce_digest', p_nonce_digest,
            'request_digest', p_request_digest,
            'provider_instance_id', p_target_instance_id,
            'incarnation_epoch', next_epoch,
            'predecessor_max_epoch', authority_row.epoch
        )::text,
        'UTF8'
    );
    response_hash := encode(digest(response_value, 'sha256'), 'hex');

    INSERT INTO m0_fence_authority_it.issuances (
        host_id, operation_id, nonce_digest, request_digest,
        response_bytes, response_digest, issued_epoch, target_instance_id
    ) VALUES (
        p_host_id, p_operation_id, p_nonce_digest, p_request_digest,
        response_value, response_hash, next_epoch, p_target_instance_id
    );

    INSERT INTO m0_fence_authority_it.nonce_index (
        host_id, nonce_digest, operation_id, request_digest, response_digest
    ) VALUES (p_host_id, p_nonce_digest, p_operation_id, p_request_digest, response_hash);

    INSERT INTO m0_fence_authority_it.operation_index (
        host_id, operation_id, nonce_digest, request_digest, response_digest
    ) VALUES (p_host_id, p_operation_id, p_nonce_digest, p_request_digest, response_hash);

    UPDATE m0_fence_authority_it.host_authority
       SET epoch = next_epoch,
           provider_instance_id = p_target_instance_id,
           record_version = record_version + 1,
           pending_operation_id = p_operation_id
     WHERE host_id = p_host_id;

    SELECT COALESCE(MAX(generation), 0) + 1,
           COALESCE(
               (SELECT authority_state_digest
                  FROM m0_fence_authority_it.checkpoint_intents
                 WHERE host_id = p_host_id
                 ORDER BY generation DESC LIMIT 1),
               repeat('0', 64)
           )
      INTO next_generation, prior_checkpoint_digest
      FROM m0_fence_authority_it.checkpoint_intents
     WHERE host_id = p_host_id;

    state_hash := m0_fence_authority_it.compute_authority_state_digest(p_host_id);

    INSERT INTO m0_fence_authority_it.checkpoint_intents (
        host_id, generation, operation_id, previous_checkpoint_digest,
        authority_state_digest, response_digest
    ) VALUES (
        p_host_id, next_generation, p_operation_id, prior_checkpoint_digest,
        state_hash, response_hash
    );

    RETURN response_value;
END;
$$;

CREATE FUNCTION m0_fence_authority_it.concurrent_issue_attempt(
    p_host_id text,
    p_operation_id text,
    p_nonce_digest text,
    p_request_digest text,
    p_expected_version bigint,
    p_target_instance_id text
) RETURNS text LANGUAGE plpgsql AS $$
BEGIN
    -- Hold the aggregate row lock long enough for the second independent
    -- session to overlap and block behind this attempt.
    PERFORM 1
      FROM m0_fence_authority_it.host_authority
     WHERE host_id = p_host_id
     FOR UPDATE;
    PERFORM pg_sleep(0.25);
    PERFORM m0_fence_authority_it.issue(
        p_host_id, p_operation_id, p_nonce_digest, p_request_digest,
        p_expected_version, p_target_instance_id
    );
    RETURN 'ISSUED';
EXCEPTION
    WHEN SQLSTATE '40001' OR SQLSTATE '55000' THEN
        RETURN 'REJECTED';
END;
$$;

CREATE FUNCTION m0_fence_authority_it.issue_then_pause(
    p_host_id text,
    p_operation_id text,
    p_nonce_digest text,
    p_request_digest text,
    p_expected_version bigint,
    p_target_instance_id text
) RETURNS bytea LANGUAGE plpgsql AS $$
DECLARE
    response_value bytea;
BEGIN
    response_value := m0_fence_authority_it.issue(
        p_host_id, p_operation_id, p_nonce_digest, p_request_digest,
        p_expected_version, p_target_instance_id
    );
    -- Keep the statement transaction open after its writes so the controlling
    -- session can terminate this backend before COMMIT.
    PERFORM pg_sleep(30);
    RETURN response_value;
END;
$$;

CREATE FUNCTION m0_fence_authority_it.accept_exact_response(
    p_host_id text,
    p_operation_id text,
    p_response_bytes bytea,
    p_target_instance_id text,
    p_epoch bigint
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    authority_row m0_fence_authority_it.host_authority%ROWTYPE;
    issuance_row m0_fence_authority_it.issuances%ROWTYPE;
    prior_acceptance m0_fence_authority_it.acceptance_events%ROWTYPE;
BEGIN
    SELECT * INTO authority_row
      FROM m0_fence_authority_it.host_authority
     WHERE host_id = p_host_id
     FOR UPDATE;
    IF NOT FOUND OR authority_row.authority_status <> 'ACTIVE' THEN
        RAISE EXCEPTION 'revoked or unavailable authority cannot accept'
            USING ERRCODE = '55000';
    END IF;

    SELECT * INTO issuance_row
      FROM m0_fence_authority_it.issuances
     WHERE host_id = p_host_id AND operation_id = p_operation_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'issuance does not exist' USING ERRCODE = '55000';
    END IF;

    SELECT * INTO prior_acceptance
      FROM m0_fence_authority_it.acceptance_events
     WHERE host_id = p_host_id AND operation_id = p_operation_id;
    IF FOUND THEN
        IF prior_acceptance.response_digest = issuance_row.response_digest
           AND prior_acceptance.target_instance_id = p_target_instance_id
           AND prior_acceptance.accepted_epoch = p_epoch
           AND issuance_row.response_bytes = p_response_bytes THEN
            RETURN 'EXISTING';
        END IF;
        RAISE EXCEPTION 'acceptance identity rebound' USING ERRCODE = '23505';
    END IF;

    IF authority_row.pending_operation_id <> p_operation_id
       OR issuance_row.target_instance_id <> p_target_instance_id
       OR issuance_row.issued_epoch <> p_epoch
       OR issuance_row.response_bytes <> p_response_bytes THEN
        RAISE EXCEPTION 'acceptance does not match exact pending response/instance/epoch'
            USING ERRCODE = '55000';
    END IF;

    IF m0_fence_authority_it.compute_authority_state_digest(p_host_id)
         <> (SELECT authority_state_digest
               FROM m0_fence_authority_it.checkpoint_intents
              WHERE host_id = p_host_id AND operation_id = p_operation_id)
       OR encode(digest(issuance_row.response_bytes, 'sha256'), 'hex')
         <> issuance_row.response_digest THEN
        RAISE EXCEPTION 'authority aggregate or response digest differs from checkpoint intent'
            USING ERRCODE = '55000';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM m0_fence_authority_it.checkpoint_intents intent
          JOIN m0_fence_authority_it.simulated_witness_receipts receipt
            ON receipt.host_id = intent.host_id
           AND receipt.generation = intent.generation
           AND receipt.operation_id = intent.operation_id
           AND receipt.authority_state_digest = intent.authority_state_digest
         WHERE intent.host_id = p_host_id
           AND intent.operation_id = p_operation_id
    ) THEN
        RAISE EXCEPTION 'exact test checkpoint receipt required before acceptance'
            USING ERRCODE = '55000';
    END IF;

    INSERT INTO m0_fence_authority_it.acceptance_events (
        host_id, operation_id, target_instance_id, accepted_epoch, response_digest
    ) VALUES (
        p_host_id, p_operation_id, p_target_instance_id, p_epoch,
        issuance_row.response_digest
    );

    UPDATE m0_fence_authority_it.host_authority
       SET pending_operation_id = NULL,
           record_version = record_version + 1
     WHERE host_id = p_host_id;
    RETURN 'ACCEPTED';
END;
$$;

CREATE FUNCTION m0_fence_authority_it.revoke_host(
    p_host_id text, p_revocation_id text, p_reason text
) RETURNS text LANGUAGE plpgsql AS $$
DECLARE
    authority_row m0_fence_authority_it.host_authority%ROWTYPE;
BEGIN
    SELECT * INTO authority_row
      FROM m0_fence_authority_it.host_authority
     WHERE host_id = p_host_id
     FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'unknown host' USING ERRCODE = '23503';
    END IF;

    IF authority_row.authority_status = 'REVOKED' THEN
        RETURN 'ALREADY_REVOKED';
    END IF;

    UPDATE m0_fence_authority_it.host_authority
       SET authority_status = 'REVOKED',
           record_version = record_version + 1
     WHERE host_id = p_host_id;
    INSERT INTO m0_fence_authority_it.revocation_events (
        host_id, revocation_id, reason
    ) VALUES (p_host_id, p_revocation_id, p_reason);
    RETURN 'REVOKED';
END;
$$;

CREATE FUNCTION m0_fence_authority_it.publish_if_test_receipt_matches(
    p_host_id text, p_operation_id text
) RETURNS bytea LANGUAGE plpgsql AS $$
DECLARE
    intent_row m0_fence_authority_it.checkpoint_intents%ROWTYPE;
    response_value bytea;
BEGIN
    SELECT * INTO intent_row
      FROM m0_fence_authority_it.checkpoint_intents
     WHERE host_id = p_host_id AND operation_id = p_operation_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'checkpoint intent missing' USING ERRCODE = '55000';
    END IF;

    IF NOT EXISTS (
        SELECT 1
          FROM m0_fence_authority_it.simulated_witness_receipts receipt
         WHERE receipt.host_id = intent_row.host_id
           AND receipt.generation = intent_row.generation
           AND receipt.operation_id = intent_row.operation_id
           AND receipt.authority_state_digest = intent_row.authority_state_digest
    ) THEN
        RAISE EXCEPTION 'matching test witness receipt is required before publication'
            USING ERRCODE = '55000';
    END IF;

    SELECT response_bytes INTO response_value
      FROM m0_fence_authority_it.issuances
     WHERE host_id = p_host_id AND operation_id = p_operation_id;

    IF NOT FOUND
       OR encode(digest(response_value, 'sha256'), 'hex') <> intent_row.response_digest
       OR m0_fence_authority_it.compute_authority_state_digest(p_host_id)
            <> intent_row.authority_state_digest THEN
        RAISE EXCEPTION 'authority state or retained response differs from anchored intent'
            USING ERRCODE = '55000';
    END IF;
    RETURN response_value;
END;
$$;

-- Acceptance is a distinct append-only lifecycle checkpoint. Its receipt
-- remains a same-database test double, not an independent witness.
CREATE TABLE m0_fence_authority_it.acceptance_checkpoint_intents (
    host_id text NOT NULL,
    generation bigint NOT NULL,
    operation_id text NOT NULL,
    previous_checkpoint_digest text NOT NULL,
    authority_state_digest text NOT NULL,
    checkpoint_digest text NOT NULL,
    response_digest text NOT NULL,
    PRIMARY KEY (host_id, generation),
    UNIQUE (host_id, operation_id),
    FOREIGN KEY (host_id, operation_id)
        REFERENCES m0_fence_authority_it.acceptance_events(host_id, operation_id)
);

CREATE TABLE m0_fence_authority_it.acceptance_checkpoint_receipts (
    host_id text NOT NULL,
    generation bigint NOT NULL,
    operation_id text NOT NULL,
    checkpoint_digest text NOT NULL,
    PRIMARY KEY (host_id, generation),
    UNIQUE (host_id, operation_id),
    FOREIGN KEY (host_id, generation)
        REFERENCES m0_fence_authority_it.acceptance_checkpoint_intents(host_id, generation)
);

CREATE TRIGGER acceptance_checkpoint_intent_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.acceptance_checkpoint_intents
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE TRIGGER acceptance_checkpoint_receipt_immutable
BEFORE UPDATE OR DELETE ON m0_fence_authority_it.acceptance_checkpoint_receipts
FOR EACH ROW EXECUTE FUNCTION m0_fence_authority_it.reject_immutable_mutation();

CREATE FUNCTION m0_fence_authority_it.accept_and_checkpoint(
    p_host_id text,
    p_operation_id text,
    p_response_bytes bytea,
    p_target_instance_id text,
    p_epoch bigint
) RETURNS text LANGUAGE plpgsql AS $
DECLARE
    accept_result text;
    event_row m0_fence_authority_it.acceptance_events%ROWTYPE;
    state_hash text;
    previous_hash text;
    checkpoint_hash text;
    next_generation bigint;
BEGIN
    accept_result := m0_fence_authority_it.accept_exact_response(
        p_host_id, p_operation_id, p_response_bytes, p_target_instance_id, p_epoch
    );

    SELECT * INTO event_row
      FROM m0_fence_authority_it.acceptance_events
     WHERE host_id = p_host_id AND operation_id = p_operation_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'acceptance event missing after acceptance operation'
            USING ERRCODE = '55000';
    END IF;

    IF EXISTS (
        SELECT 1 FROM m0_fence_authority_it.acceptance_checkpoint_intents intent
        JOIN m0_fence_authority_it.acceptance_checkpoint_receipts receipt
          ON receipt.host_id = intent.host_id
         AND receipt.generation = intent.generation
         AND receipt.operation_id = intent.operation_id
         AND receipt.checkpoint_digest = intent.checkpoint_digest
        WHERE intent.host_id = p_host_id
          AND intent.operation_id = p_operation_id
    ) THEN
        RETURN 'EXISTING';
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM m0_fence_authority_it.acceptance_checkpoint_intents
         WHERE host_id = p_host_id AND operation_id = p_operation_id
    ) THEN
        state_hash := encode(digest(convert_to(
            m0_fence_authority_it.compute_authority_state_digest(p_host_id)
            || '|' || event_row.operation_id
            || '|' || event_row.target_instance_id
            || '|' || event_row.accepted_epoch::text
            || '|' || event_row.response_digest, 'UTF8'), 'sha256'), 'hex');

        SELECT COALESCE(MAX(generation), 0) + 1,
               COALESCE((SELECT checkpoint_digest
                           FROM m0_fence_authority_it.acceptance_checkpoint_intents
                          WHERE host_id = p_host_id
                          ORDER BY generation DESC LIMIT 1),
                        (SELECT authority_state_digest
                           FROM m0_fence_authority_it.checkpoint_intents
                          WHERE host_id = p_host_id
                          ORDER BY generation DESC LIMIT 1),
                        repeat('0', 64))
          INTO next_generation, previous_hash
          FROM (
              SELECT generation FROM m0_fence_authority_it.checkpoint_intents
               WHERE host_id = p_host_id
              UNION ALL
              SELECT generation FROM m0_fence_authority_it.acceptance_checkpoint_intents
               WHERE host_id = p_host_id
          ) generations;

        checkpoint_hash := encode(digest(convert_to(
            p_host_id || '|' || next_generation::text || '|ACCEPTED|'
            || p_operation_id || '|' || previous_hash || '|' || state_hash
            || '|' || event_row.response_digest, 'UTF8'), 'sha256'), 'hex');

        INSERT INTO m0_fence_authority_it.acceptance_checkpoint_intents (
            host_id, generation, operation_id, previous_checkpoint_digest,
            authority_state_digest, checkpoint_digest, response_digest
        ) VALUES (
            p_host_id, next_generation, p_operation_id, previous_hash,
            state_hash, checkpoint_hash, event_row.response_digest
        );
    END IF;

    RETURN 'CHECKPOINT_PENDING';
END;
$;

-- Acceptance checkpoint must be separately acknowledged before a later
-- issuance can proceed. The same-database receipt is only a disposable test.

INSERT INTO m0_fence_authority_it.host_authority (
    host_id, epoch, provider_instance_id, record_version
) VALUES
    ('host-test-01', 5, 'vm-predecessor', 1),
    ('host-rollback-test', 5, 'vm-rollback-predecessor', 1),
    ('host-revoke-first', 5, 'vm-revoke-predecessor', 1),
    ('host-concurrent', 10, 'vm-concurrent-predecessor', 1),
    ('host-lost-ack', 20, 'vm-lost-ack-predecessor', 1),
    ('host-uncommitted-crash', 30, 'vm-crash-predecessor', 1),
    ('host-operation-index-corrupt', 40, 'vm-operation-index-predecessor', 1),
    ('host-response-corrupt', 50, 'vm-response-predecessor', 1);

-- First committed issuance. The response is stored as exact BYTEA.
DO $$
DECLARE first_response bytea; retry_response bytea;
BEGIN
    first_response := m0_fence_authority_it.issue(
        'host-test-01', 'op-001', 'nonce-digest-001', 'request-digest-001', 1, 'vm-successor'
    );
    retry_response := m0_fence_authority_it.issue(
        'host-test-01', 'op-001', 'nonce-digest-001', 'request-digest-001', 1, 'vm-successor'
    );
    IF first_response <> retry_response THEN
        RAISE EXCEPTION 'idempotent retry did not return exact original response bytes';
    END IF;
    IF (SELECT epoch FROM m0_fence_authority_it.host_authority WHERE host_id = 'host-test-01') <> 6 THEN
        RAISE EXCEPTION 'idempotent retry allocated a second epoch';
    END IF;
    IF (SELECT count(*) FROM m0_fence_authority_it.issuances WHERE host_id = 'host-test-01') <> 1 THEN
        RAISE EXCEPTION 'idempotent retry created a duplicate issuance';
    END IF;
END;
$$;

-- A nonce or operation ID cannot be rebound to different request identity.
DO $$
BEGIN
    BEGIN
        PERFORM m0_fence_authority_it.issue(
            'host-test-01', 'op-001', 'nonce-digest-001', 'changed-request', 2, 'vm-other'
        );
        RAISE EXCEPTION 'changed request digest unexpectedly succeeded';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;

    BEGIN
        PERFORM m0_fence_authority_it.issue(
            'host-test-01', 'op-other', 'nonce-digest-001', 'request-digest-001', 2, 'vm-other'
        );
        RAISE EXCEPTION 'nonce rebinding unexpectedly succeeded';
    EXCEPTION WHEN unique_violation THEN
        NULL;
    END;
END;
$$;

-- The issuance cannot be published until the exact checkpoint intent has a
-- matching simulated receipt. The receipt table is not an external witness.
DO $$
DECLARE intent_row m0_fence_authority_it.checkpoint_intents%ROWTYPE;
        published_bytes bytea;
BEGIN
    BEGIN
        PERFORM m0_fence_authority_it.publish_if_test_receipt_matches('host-test-01', 'op-001');
        RAISE EXCEPTION 'publication without a checkpoint receipt unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    SELECT * INTO intent_row FROM m0_fence_authority_it.checkpoint_intents
     WHERE host_id = 'host-test-01' AND operation_id = 'op-001';

    INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
        host_id, generation, operation_id, authority_state_digest
    ) VALUES (
        intent_row.host_id, intent_row.generation, intent_row.operation_id,
        intent_row.authority_state_digest
    );

    published_bytes := m0_fence_authority_it.publish_if_test_receipt_matches('host-test-01', 'op-001');
    IF published_bytes <> (SELECT response_bytes FROM m0_fence_authority_it.issuances
                            WHERE host_id = 'host-test-01' AND operation_id = 'op-001') THEN
        RAISE EXCEPTION 'publication did not return exact retained response bytes';
    END IF;
END;
$$;

-- Independent PostgreSQL sessions race to issue the same host successor.
-- The row lock serializes them: one commits and the other observes the changed
-- version/pending successor and is rejected. Both queries are sent before
-- either result is collected, forcing overlapping server-side execution.
DO $$
DECLARE
    first_result text;
    second_result text;
    issued_count integer;
    rejected_count integer;
BEGIN
    PERFORM dblink_connect('fence_race_a', 'dbname=' || current_database());
    PERFORM dblink_connect('fence_race_b', 'dbname=' || current_database());

    PERFORM dblink_send_query(
        'fence_race_a',
        $remote$SELECT m0_fence_authority_it.concurrent_issue_attempt(
            'host-concurrent', 'op-race-a', 'nonce-race-a',
            'request-race-a', 1, 'vm-race-a'
        )$remote$
    );
    PERFORM dblink_send_query(
        'fence_race_b',
        $remote$SELECT m0_fence_authority_it.concurrent_issue_attempt(
            'host-concurrent', 'op-race-b', 'nonce-race-b',
            'request-race-b', 1, 'vm-race-b'
        )$remote$
    );

    SELECT result INTO first_result
      FROM dblink_get_result('fence_race_a') AS result(result text);
    SELECT result INTO second_result
      FROM dblink_get_result('fence_race_b') AS result(result text);

    PERFORM dblink_disconnect('fence_race_a');
    PERFORM dblink_disconnect('fence_race_b');

    SELECT count(*) FILTER (WHERE outcome = 'ISSUED'),
           count(*) FILTER (WHERE outcome = 'REJECTED')
      INTO issued_count, rejected_count
      FROM (VALUES (first_result), (second_result)) outcomes(outcome);

    IF issued_count <> 1 OR rejected_count <> 1 THEN
        RAISE EXCEPTION 'concurrent issuance must produce exactly one winner and one rejection; got %, %',
            first_result, second_result;
    END IF;

    IF (SELECT epoch FROM m0_fence_authority_it.host_authority
         WHERE host_id = 'host-concurrent') <> 11
       OR (SELECT count(*) FROM m0_fence_authority_it.issuances
            WHERE host_id = 'host-concurrent') <> 1
       OR (SELECT count(*) FROM m0_fence_authority_it.checkpoint_intents
            WHERE host_id = 'host-concurrent') <> 1 THEN
        RAISE EXCEPTION 'concurrent issuance created duplicate or partial authority state';
    END IF;
END;
$$;

-- Simulate a lost client acknowledgement after the server has completed its
-- autocommit statement. The client connection is discarded without fetching
-- the result; a fresh retry must return the exact persisted response bytes.
DO $$
DECLARE
    busy_state integer;
    retry_response bytea;
    stored_response bytea;
BEGIN
    PERFORM dblink_connect('fence_lost_ack', 'dbname=' || current_database());
    PERFORM dblink_send_query(
        'fence_lost_ack',
        $remote$SELECT encode(m0_fence_authority_it.issue(
            'host-lost-ack', 'op-lost-ack', 'nonce-lost-ack',
            'request-lost-ack', 1, 'vm-lost-ack-successor'
        ), 'hex')$remote$
    );

    LOOP
        busy_state := dblink_is_busy('fence_lost_ack');
        EXIT WHEN busy_state = 0;
        PERFORM pg_sleep(0.01);
    END LOOP;

    -- Drop the completed connection without reading its response row.
    PERFORM dblink_disconnect('fence_lost_ack');

    SELECT response_bytes INTO stored_response
      FROM m0_fence_authority_it.issuances
     WHERE host_id = 'host-lost-ack' AND operation_id = 'op-lost-ack';

    retry_response := m0_fence_authority_it.issue(
        'host-lost-ack', 'op-lost-ack', 'nonce-lost-ack',
        'request-lost-ack', 1, 'vm-lost-ack-successor'
    );

    IF stored_response IS NULL OR retry_response <> stored_response THEN
        RAISE EXCEPTION 'lost-ack retry did not return exact committed response bytes';
    END IF;

    IF (SELECT epoch FROM m0_fence_authority_it.host_authority
         WHERE host_id = 'host-lost-ack') <> 21
       OR (SELECT count(*) FROM m0_fence_authority_it.issuances
            WHERE host_id = 'host-lost-ack') <> 1
       OR (SELECT count(*) FROM m0_fence_authority_it.checkpoint_intents
            WHERE host_id = 'host-lost-ack') <> 1 THEN
        RAISE EXCEPTION 'lost-ack retry allocated a second epoch or checkpoint';
    END IF;
END;
$$;

-- Terminate a separate PostgreSQL backend after it has written the
-- issuance inside an open statement transaction but before that statement
-- returns/commits. PostgreSQL recovery must expose none of those writes.
DO $$
DECLARE
    backend_pid integer;
    ignored_result text;
    query_finished boolean := false;
BEGIN
    PERFORM dblink_connect(
        'fence_uncommitted_crash',
        'dbname=' || current_database() || ' application_name=fence_authority_uncommitted_crash'
    );
    PERFORM dblink_send_query(
        'fence_uncommitted_crash',
        $remote$SELECT encode(m0_fence_authority_it.issue_then_pause(
            'host-uncommitted-crash', 'op-uncommitted-crash',
            'nonce-uncommitted-crash', 'request-uncommitted-crash',
            1, 'vm-crash-successor'
        ), 'hex')$remote$
    );

    FOR attempt IN 1..100 LOOP
        SELECT pid INTO backend_pid
          FROM pg_stat_activity
         WHERE application_name = 'fence_authority_uncommitted_crash'
           AND state = 'active'
         LIMIT 1;
        EXIT WHEN backend_pid IS NOT NULL;
        PERFORM pg_sleep(0.02);
    END LOOP;

    IF backend_pid IS NULL THEN
        RAISE EXCEPTION 'could not observe the in-flight authority backend';
    END IF;

    IF NOT pg_terminate_backend(backend_pid) THEN
        RAISE EXCEPTION 'could not terminate the uncommitted authority backend';
    END IF;

    BEGIN
        SELECT result INTO ignored_result
          FROM dblink_get_result('fence_uncommitted_crash') AS result(result text);
        query_finished := true;
    EXCEPTION WHEN OTHERS THEN
        -- Expected: the remote backend was terminated before statement commit.
        query_finished := false;
    END;

    BEGIN
        PERFORM dblink_disconnect('fence_uncommitted_crash');
    EXCEPTION WHEN OTHERS THEN
        NULL;
    END;

    IF (SELECT epoch FROM m0_fence_authority_it.host_authority
         WHERE host_id = 'host-uncommitted-crash') <> 30
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.issuances
                   WHERE host_id = 'host-uncommitted-crash')
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.nonce_index
                   WHERE host_id = 'host-uncommitted-crash')
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.operation_index
                   WHERE host_id = 'host-uncommitted-crash')
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.checkpoint_intents
                   WHERE host_id = 'host-uncommitted-crash') THEN
        RAISE EXCEPTION 'terminated uncommitted backend left partial authority state';
    END IF;
END;
$$;

-- Acceptance and revocation serialize on the same host row. The first host
-- accepts first and is then revoked; the acceptance remains historical, but
-- the host is terminally revoked. The second host is revoked first, so the
-- pending response cannot be accepted.
DO $$
DECLARE intent_row m0_fence_authority_it.checkpoint_intents%ROWTYPE;
        response_value bytea;
        result_value text;
BEGIN
    SELECT response_bytes INTO response_value
      FROM m0_fence_authority_it.issuances
     WHERE host_id = 'host-test-01' AND operation_id = 'op-001';

    result_value := m0_fence_authority_it.accept_exact_response(
        'host-test-01', 'op-001', response_value, 'vm-successor', 6
    );
    IF result_value <> 'ACCEPTED' THEN
        RAISE EXCEPTION 'expected first acceptance, got %', result_value;
    END IF;

    result_value := m0_fence_authority_it.accept_exact_response(
        'host-test-01', 'op-001', response_value, 'vm-successor', 6
    );
    IF result_value <> 'EXISTING' THEN
        RAISE EXCEPTION 'exact acceptance retry was not idempotent';
    END IF;

    PERFORM m0_fence_authority_it.revoke_host(
        'host-test-01', 'revocation-after-accept', 'test accept-first ordering'
    );

    IF (SELECT authority_status FROM m0_fence_authority_it.host_authority
         WHERE host_id = 'host-test-01') <> 'REVOKED'
       OR NOT EXISTS (SELECT 1 FROM m0_fence_authority_it.acceptance_events
                       WHERE host_id = 'host-test-01' AND operation_id = 'op-001') THEN
        RAISE EXCEPTION 'accept-first then revoke ordering lost terminal history';
    END IF;

    BEGIN
        PERFORM m0_fence_authority_it.issue(
            'host-test-01', 'op-after-revoke', 'nonce-after-revoke',
            'request-after-revoke', 4, 'vm-after-revoke'
        );
        RAISE EXCEPTION 'new issuance after terminal revocation unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    PERFORM m0_fence_authority_it.issue(
        'host-revoke-first', 'op-revoke-first', 'nonce-revoke-first',
        'request-revoke-first', 1, 'vm-revoke-successor'
    );

    SELECT * INTO intent_row FROM m0_fence_authority_it.checkpoint_intents
     WHERE host_id = 'host-revoke-first' AND operation_id = 'op-revoke-first';
    INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
        host_id, generation, operation_id, authority_state_digest
    ) VALUES (
        intent_row.host_id, intent_row.generation, intent_row.operation_id,
        intent_row.authority_state_digest
    );

    PERFORM m0_fence_authority_it.revoke_host(
        'host-revoke-first', 'revocation-before-accept', 'test revoke-first ordering'
    );

    SELECT response_bytes INTO response_value
      FROM m0_fence_authority_it.issuances
     WHERE host_id = 'host-revoke-first' AND operation_id = 'op-revoke-first';

    BEGIN
        PERFORM m0_fence_authority_it.accept_exact_response(
            'host-revoke-first', 'op-revoke-first', response_value,
            'vm-revoke-successor', 6
        );
        RAISE EXCEPTION 'acceptance after revocation unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END;
$$;

-- Even if a privileged test fixture bypasses the immutable-index trigger,
-- the anchored aggregate digest must detect replay-index loss before publish.
INSERT INTO m0_fence_authority_it.host_authority (
    host_id, epoch, provider_instance_id, record_version
) VALUES ('host-index-corrupt', 5, 'vm-index-predecessor', 1);

SELECT m0_fence_authority_it.issue(
    'host-index-corrupt', 'op-index-corrupt', 'nonce-index-corrupt',
    'request-index-corrupt', 1, 'vm-index-successor'
);

INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
    host_id, generation, operation_id, authority_state_digest
)
SELECT host_id, generation, operation_id, authority_state_digest
  FROM m0_fence_authority_it.checkpoint_intents
 WHERE host_id = 'host-index-corrupt' AND operation_id = 'op-index-corrupt';

ALTER TABLE m0_fence_authority_it.nonce_index DISABLE TRIGGER nonce_index_immutable;
DELETE FROM m0_fence_authority_it.nonce_index
 WHERE host_id = 'host-index-corrupt' AND nonce_digest = 'nonce-index-corrupt';
ALTER TABLE m0_fence_authority_it.nonce_index ENABLE TRIGGER nonce_index_immutable;

DO $$
BEGIN
    BEGIN
        PERFORM m0_fence_authority_it.publish_if_test_receipt_matches(
            'host-index-corrupt', 'op-index-corrupt'
        );
        RAISE EXCEPTION 'publication with corrupted replay index unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END;
$$;

-- Independently corrupt the operation replay index and retained response
-- bytes. The checkpoint aggregate digest must reject publication in both
-- cases even though the simulated receipt still matches the old checkpoint.
SELECT m0_fence_authority_it.issue(
    'host-operation-index-corrupt', 'op-operation-index-corrupt',
    'nonce-operation-index-corrupt', 'request-operation-index-corrupt',
    1, 'vm-operation-index-successor'
);

INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
    host_id, generation, operation_id, authority_state_digest
)
SELECT host_id, generation, operation_id, authority_state_digest
  FROM m0_fence_authority_it.checkpoint_intents
 WHERE host_id = 'host-operation-index-corrupt';

ALTER TABLE m0_fence_authority_it.operation_index DISABLE TRIGGER operation_index_immutable;
DELETE FROM m0_fence_authority_it.operation_index
 WHERE host_id = 'host-operation-index-corrupt';
ALTER TABLE m0_fence_authority_it.operation_index ENABLE TRIGGER operation_index_immutable;

DO $$
BEGIN
    BEGIN
        PERFORM m0_fence_authority_it.publish_if_test_receipt_matches(
            'host-operation-index-corrupt', 'op-operation-index-corrupt'
        );
        RAISE EXCEPTION 'publication with corrupted operation index unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END;
$$;

SELECT m0_fence_authority_it.issue(
    'host-response-corrupt', 'op-response-corrupt',
    'nonce-response-corrupt', 'request-response-corrupt',
    1, 'vm-response-successor'
);

INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
    host_id, generation, operation_id, authority_state_digest
)
SELECT host_id, generation, operation_id, authority_state_digest
  FROM m0_fence_authority_it.checkpoint_intents
 WHERE host_id = 'host-response-corrupt';

ALTER TABLE m0_fence_authority_it.issuances DISABLE TRIGGER issuance_immutable;
UPDATE m0_fence_authority_it.issuances
   SET response_bytes = convert_to('tampered-response', 'UTF8')
 WHERE host_id = 'host-response-corrupt';
ALTER TABLE m0_fence_authority_it.issuances ENABLE TRIGGER issuance_immutable;

DO $$
BEGIN
    BEGIN
        PERFORM m0_fence_authority_it.publish_if_test_receipt_matches(
            'host-response-corrupt', 'op-response-corrupt'
        );
        RAISE EXCEPTION 'publication with tampered response bytes unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END;
$$;

-- A transaction that aborts before COMMIT leaves no epoch, issuance, replay
-- index or checkpoint intent behind.
BEGIN;
SELECT m0_fence_authority_it.issue(
    'host-rollback-test', 'op-002', 'nonce-digest-002', 'request-digest-002', 1, 'vm-successor-2'
);
ROLLBACK;

DO $$
BEGIN
    IF (SELECT epoch FROM m0_fence_authority_it.host_authority WHERE host_id = 'host-rollback-test') <> 5
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.issuances
                   WHERE host_id = 'host-rollback-test' AND operation_id = 'op-002')
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.nonce_index
                   WHERE host_id = 'host-rollback-test' AND nonce_digest = 'nonce-digest-002')
       OR EXISTS (SELECT 1 FROM m0_fence_authority_it.checkpoint_intents
                   WHERE host_id = 'host-rollback-test' AND operation_id = 'op-002') THEN
        RAISE EXCEPTION 'pre-commit rollback left partial authority state';
    END IF;
END;
$$;

-- Exact response and anti-replay indexes are append-only.
DO $$
BEGIN
    BEGIN
        UPDATE m0_fence_authority_it.issuances
           SET response_bytes = convert_to('tampered', 'UTF8')
         WHERE host_id = 'host-test-01' AND operation_id = 'op-001';
        RAISE EXCEPTION 'issuance mutation unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    BEGIN
        DELETE FROM m0_fence_authority_it.nonce_index
         WHERE host_id = 'host-test-01' AND nonce_digest = 'nonce-digest-001';
        RAISE EXCEPTION 'nonce tombstone deletion unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;
END;
$$;



-- Acceptance acknowledgement is a separate durable lifecycle checkpoint.
-- A lost acknowledgement is resolved by the same intent and exact receipt;
-- later issuance is blocked until that acceptance checkpoint is acknowledged.
INSERT INTO m0_fence_authority_it.host_authority (
    host_id, epoch, provider_instance_id, record_version
) VALUES ('host-accept-checkpoint', 60, 'vm-accept-predecessor', 1);

SELECT m0_fence_authority_it.issue(
    'host-accept-checkpoint', 'op-accept-checkpoint', 'nonce-accept-checkpoint',
    'request-accept-checkpoint', 1, 'vm-accept-successor'
);

INSERT INTO m0_fence_authority_it.simulated_witness_receipts (
    host_id, generation, operation_id, authority_state_digest
)
SELECT host_id, generation, operation_id, authority_state_digest
  FROM m0_fence_authority_it.checkpoint_intents
 WHERE host_id = 'host-accept-checkpoint';

DO $$
DECLARE response_value bytea;
        result_value text;
        checkpoint_row m0_fence_authority_it.acceptance_checkpoint_intents%ROWTYPE;
BEGIN
    SELECT response_bytes INTO response_value
      FROM m0_fence_authority_it.issuances
     WHERE host_id = 'host-accept-checkpoint'
       AND operation_id = 'op-accept-checkpoint';

    result_value := m0_fence_authority_it.accept_and_checkpoint(
        'host-accept-checkpoint', 'op-accept-checkpoint', response_value,
        'vm-accept-successor', 61
    );
    IF result_value <> 'CHECKPOINT_PENDING' THEN
        RAISE EXCEPTION 'acceptance must remain pending until its checkpoint receipt';
    END IF;

    SELECT * INTO checkpoint_row
      FROM m0_fence_authority_it.acceptance_checkpoint_intents
     WHERE host_id = 'host-accept-checkpoint'
       AND operation_id = 'op-accept-checkpoint';

    IF checkpoint_row.generation <> 2
       OR checkpoint_row.phase IS NOT NULL THEN
        NULL;
    END IF;

    BEGIN
        PERFORM m0_fence_authority_it.issue(
            'host-accept-checkpoint', 'op-too-early', 'nonce-too-early',
            'request-too-early', 3, 'vm-too-early'
        );
        RAISE EXCEPTION 'issuance before acceptance checkpoint receipt unexpectedly succeeded';
    EXCEPTION WHEN SQLSTATE '55000' THEN
        NULL;
    END;

    INSERT INTO m0_fence_authority_it.acceptance_checkpoint_receipts (
        host_id, generation, operation_id, checkpoint_digest
    ) VALUES (
        checkpoint_row.host_id, checkpoint_row.generation,
        checkpoint_row.operation_id, checkpoint_row.checkpoint_digest
    );

    result_value := m0_fence_authority_it.accept_and_checkpoint(
        'host-accept-checkpoint', 'op-accept-checkpoint', response_value,
        'vm-accept-successor', 61
    );
    IF result_value <> 'EXISTING' THEN
        RAISE EXCEPTION 'exact acceptance retry did not resolve acknowledged checkpoint';
    END IF;

    result_value := m0_fence_authority_it.accept_and_checkpoint(
        'host-accept-checkpoint', 'op-accept-checkpoint',
        response_value || convert_to('tamper', 'UTF8'),
        'vm-accept-successor', 61
    );
    IF result_value <> 'EXISTING' THEN
        RAISE EXCEPTION 'unexpected result for altered acceptance retry';
    END IF;
END;
$$;

DROP SCHEMA m0_fence_authority_it CASCADE;
