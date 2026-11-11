package lifecycle

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func newTestTrigger(id string, bootTime time.Duration) Trigger {
	return Trigger{
		ID:                  id,
		Kind:                "deadline",
		AuthenticatedSource: "host-deadline-controller",
		BootID:              "boot-1",
		ObservedBootTime:    bootTime,
		ObservedAtUTC:       time.Date(2026, time.November, 11, 12, 0, 0, 0, time.UTC),
	}
}

func TestTriggerArbiterPreservesPrimaryAndClassifiesLaterTriggers(t *testing.T) {
	t.Parallel()

	arbiter, err := NewTriggerArbiter("boot-1")
	if err != nil {
		t.Fatal(err)
	}

	primary, err := arbiter.Capture(StateRunning, newTestTrigger("trigger-1", time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if primary.Sequence != 1 || primary.Disposition != TriggerPrimary {
		t.Fatalf("first trigger = %+v, want sequence 1 PRIMARY", primary)
	}

	secondary, err := arbiter.Capture(StateTerminating, newTestTrigger("trigger-2", 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if secondary.Sequence != 2 || secondary.Disposition != TriggerSecondary {
		t.Fatalf("second trigger = %+v, want sequence 2 SECONDARY", secondary)
	}

	arbiter.BeginFinalization()
	late, err := arbiter.Capture(StateFinalizing, newTestTrigger("trigger-3", 3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if late.Sequence != 3 || late.Disposition != TriggerLate {
		t.Fatalf("late trigger = %+v, want sequence 3 LATE", late)
	}

	gotPrimary, ok := arbiter.Primary()
	if !ok || gotPrimary.ID != "trigger-1" || gotPrimary.Sequence != 1 {
		t.Fatalf("primary = %+v, present = %t; want immutable trigger-1", gotPrimary, ok)
	}
}

func TestTriggerArbiterRejectsInvalidIdentityAndClock(t *testing.T) {
	t.Parallel()

	arbiter, err := NewTriggerArbiter("boot-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err := NewTriggerArbiter(" "); !errors.Is(err, ErrInvalidTrigger) {
		t.Fatalf("empty boot ID error = %v, want ErrInvalidTrigger", err)
	}

	invalid := newTestTrigger("trigger-invalid", time.Second)
	invalid.AuthenticatedSource = ""
	if _, err := arbiter.Capture(StateRunning, invalid); !errors.Is(err, ErrInvalidTrigger) {
		t.Fatalf("missing source error = %v, want ErrInvalidTrigger", err)
	}

	wrongBoot := newTestTrigger("trigger-wrong-boot", time.Second)
	wrongBoot.BootID = "boot-2"
	if _, err := arbiter.Capture(StateRunning, wrongBoot); !errors.Is(err, ErrBootIdentity) {
		t.Fatalf("wrong boot error = %v, want ErrBootIdentity", err)
	}

	if _, err := arbiter.Capture(StateRunning, newTestTrigger("trigger-first", 2*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := arbiter.Capture(StateRunning, newTestTrigger("trigger-backwards", time.Second)); !errors.Is(err, ErrClockRollback) {
		t.Fatalf("backwards clock error = %v, want ErrClockRollback", err)
	}
}

func TestTriggerArbiterConcurrentCaptureHasOnePrimaryAndOrderedSequences(t *testing.T) {
	t.Parallel()

	const count = 64
	arbiter, err := NewTriggerArbiter("boot-1")
	if err != nil {
		t.Fatal(err)
	}

	type result struct {
		record TriggerRecord
		err    error
	}
	results := make(chan result, count)
	var wait sync.WaitGroup

	for index := 0; index < count; index++ {
		index := index
		wait.Add(1)
		go func() {
			defer wait.Done()
			trigger := newTestTrigger(fmt.Sprintf("trigger-%02d", index), time.Second)
			record, captureErr := arbiter.Capture(StateRunning, trigger)
			results <- result{record: record, err: captureErr}
		}()
	}

	wait.Wait()
	close(results)

	sequences := make(map[uint64]bool, count)
	primaryCount := 0
	secondaryCount := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("Capture() error = %v", result.err)
		}
		if sequences[result.record.Sequence] {
			t.Fatalf("duplicate sequence %d", result.record.Sequence)
		}
		sequences[result.record.Sequence] = true
		switch result.record.Disposition {
		case TriggerPrimary:
			primaryCount++
		case TriggerSecondary:
			secondaryCount++
		default:
			t.Fatalf("unexpected disposition %q", result.record.Disposition)
		}
	}

	if primaryCount != 1 || secondaryCount != count-1 {
		t.Fatalf("primary count = %d, secondary count = %d; want 1 and %d", primaryCount, secondaryCount, count-1)
	}
	for sequence := uint64(1); sequence <= count; sequence++ {
		if !sequences[sequence] {
			t.Fatalf("missing sequence %d", sequence)
		}
	}
}
