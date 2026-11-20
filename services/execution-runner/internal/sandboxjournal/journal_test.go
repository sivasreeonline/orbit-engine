package sandboxjournal

import (
	"encoding/json"
	"io"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testRunnerID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
const testExecutionID = "exec_test_01"
const testContainerID = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func privateTempDir(t *testing.T) string {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	return directory
}

func TestReadBoundedJournalRejectsGrowthPastSizeLimit(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "oversized.jsonl")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxJournalSize + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		file.Close()
		t.Fatal(err)
	}
	_, err = readBoundedJournal(file)
	if err == nil || !strings.Contains(err.Error(), "exceeds size limit") {
		t.Fatalf("bounded read error = %v, want journal size limit", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalPersistsLifecycleTransitionsAndRecoversPending(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := journal.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		pending[0].Created || pending[0].Cleaned || pending[0].ContainerID != "" {
		t.Fatalf("intent pending state = %+v", pending)
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, err = reopened.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != testContainerID {
		t.Fatalf("recovered created state = %+v", pending)
	}
	if err := reopened.Cleaned(lifecycleID); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}

	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	pending, err = final.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("cleaned lifecycle still pending: %+v", pending)
	}
}

func TestJournalRejectsConcurrentOwnerAndDoesNotStealLock(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	first, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second owner error = %v, want ErrLocked", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := Open(path)
	if err != nil {
		t.Fatalf("open after clean release: %v", err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestJournalTruncatesOnlyIncompleteTrailingRecord(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{incomplete"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer recovered.Close()
	pending, err := recovered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("recovery lost valid intent: %+v", pending)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), "incomplete") {
		t.Fatal("incomplete trailing bytes were not truncated")
	}
}

func TestJournalRejectsTrailingJSONOnCompleteRecord(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	content = []byte(strings.TrimSuffix(string(content), "\n") + " {}\n")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("trailing JSON data on a complete record was accepted")
	}
}

func TestJournalRejectsMalformedCompleteRecord(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	if err := os.WriteFile(path, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("malformed complete record was accepted")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed open left an owned lock behind: %v", err)
	}
}

func TestJournalRejectsInvalidTransitionsAndIdentifiers(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer journal.Close()

	if _, err := journal.Begin("not-a-runner-id", testExecutionID); err == nil {
		t.Fatal("invalid runner instance ID accepted")
	}
	if _, err := journal.Begin(testRunnerID, "bad execution id"); err == nil {
		t.Fatal("invalid execution ID accepted")
	}
	if err := journal.Created(strings.Repeat("a", 32), testContainerID); !errors.Is(err, ErrConflict) {
		t.Fatalf("unknown lifecycle transition error = %v, want conflict", err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrConflict) {
		t.Fatalf("clean-before-created error = %v, want conflict", err)
	}
	if err := journal.Created(lifecycleID, "not-a-container-id"); err == nil {
		t.Fatal("invalid container ID accepted")
	}
	if err := journal.Created(lifecycleID, "0123456789abcdef"); err == nil {
		t.Fatal("abbreviated container ID accepted by durable journal")
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Created(lifecycleID, testContainerID); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate created event error = %v, want conflict", err)
	}
	if err := journal.Cleaned(lifecycleID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate cleaned event error = %v, want conflict", err)
	}
}

func TestJournalRejectsSymlinkAndPermissiveExistingFile(t *testing.T) {
	directory := privateTempDir(t)
	target := filepath.Join(directory, "target.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(target); err == nil {
		t.Fatal("permissive existing journal was accepted")
	}

	if err := os.Chmod(target, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "linked.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable on this platform: %v", err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlinked journal was accepted")
	}
}

func TestReadOnlyJournalAllowsInspectionButRejectsMutation(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	created, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := created.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := created.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}

	readOnly, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := readOnly.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || !pending[0].Created || pending[0].ContainerID != testContainerID {
		t.Fatalf("read-only journal state = %+v", pending)
	}
	if _, err := readOnly.Begin(testRunnerID, testExecutionID); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("read-only mutation error = %v, want ErrReadOnly", err)
	}
	if err := readOnly.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReadOnlyJournalRejectsIncompleteTailWithoutTruncating(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sandbox.jsonl")
	created, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := created.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := created.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"partial":`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := OpenReadOnly(path); err == nil {
		t.Fatal("read-only open accepted an incomplete final record")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("read-only open truncated or otherwise modified the journal")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed read-only open left its lock behind: %v", err)
	}
}


func TestJournalRecoveryPreservesCreatedStateAfterPartialCleanedTail(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "partial-cleaned.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	// Simulate a process or storage failure during the CLEANED append:
	// the final JSONL record has bytes on disk but no terminating newline.
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	partialCleaned := `{"version":1,"sequence":3,"type":"CLEANED","lifecycleId":"` + lifecycleID
	if _, err := file.WriteString(partialCleaned); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatalf("recover journal with incomplete CLEANED tail: %v", err)
	}
	pending, err := recovered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		!pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != testContainerID {
		t.Fatalf("partial CLEANED tail must preserve prior CREATED evidence: %+v", pending)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(content), partialCleaned) {
		t.Fatal("incomplete CLEANED bytes were not truncated")
	}

	// The next valid event must continue from the last durable sequence and
	// may be appended only as a fresh, complete transition.
	recovered, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Cleaned(lifecycleID); err != nil {
		t.Fatalf("append CLEANED after incomplete-tail recovery: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	pending, err = final.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("valid post-recovery CLEANED transition remained pending: %+v", pending)
	}
}


func TestJournalStopsAppendingAfterWriteOutcomeBecomesUncertain(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "uncertain-append.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}

	// /dev/full accepts open/stat but rejects writes with ENOSPC. Swap only
	// the private test handle to inject a failure after append preflight.
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if err != nil {
		_ = journal.Close()
		t.Skipf("write-failure fixture /dev/full unavailable: %v", err)
	}
	original := journal.file
	journal.file = full
	appendErr := journal.Cleaned(lifecycleID)
	journal.file = original
	if err := full.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(appendErr, ErrAppendUncertain) {
		t.Fatalf("first CLEANED append error = %v, want ErrAppendUncertain", appendErr)
	}

	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrAppendUncertain) {
		t.Fatalf("second CLEANED append error = %v, want poisoned journal rejection", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after uncertain append: %v", err)
	}
	defer recovered.Close()
	pending, err := recovered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		!pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != testContainerID {
		t.Fatalf("failed append must preserve prior CREATED evidence: %+v", pending)
	}
}


func TestJournalRecoversCompleteCleanedRecordAfterSyncReportsError(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sync-uncertain-cleaned.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected sync acknowledgement failure")
	calls := 0
	journal.syncFn = func(file *os.File) error {
		calls++
		if calls == 1 {
			// Persist the complete record, then simulate the filesystem
			// reporting an error to the caller despite the successful sync.
			if err := file.Sync(); err != nil {
				return err
			}
			return injected
		}
		return file.Sync()
	}

	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrAppendUncertain) {
		t.Fatalf("CLEANED append error = %v, want ErrAppendUncertain", err)
	}
	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrAppendUncertain) {
		t.Fatalf("second CLEANED append error = %v, want poisoned journal rejection", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close after recoverable sync uncertainty: %v", err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatalf("reopen after sync uncertainty: %v", err)
	}
	defer recovered.Close()
	pending, err := recovered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("complete durable CLEANED event should be applied on reopen: %+v", pending)
	}
}


func TestJournalRecoveryPreservesCreatedStateAfterSyncErrorLeavesIncompleteCleanedTail(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "sync-incomplete-cleaned.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
	if err != nil {
		t.Fatal(err)
	}
	if err := journal.Created(lifecycleID, testContainerID); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected sync failure after partial tail")
	calls := 0
	journal.syncFn = func(file *os.File) error {
		calls++
		if calls == 1 {
			info, err := file.Stat()
			if err != nil {
				return err
			}
			// Model a storage failure that leaves only a partial CLEANED
			// JSONL record. The newline and final bytes are absent.
			if err := file.Truncate(info.Size() - 8); err != nil {
				return err
			}
			if err := file.Sync(); err != nil {
				return err
			}
			return injected
		}
		return file.Sync()
	}

	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrAppendUncertain) {
		t.Fatalf("CLEANED append error = %v, want ErrAppendUncertain", err)
	}
	if err := journal.Cleaned(lifecycleID); !errors.Is(err, ErrAppendUncertain) {
		t.Fatalf("second CLEANED append error = %v, want poisoned journal rejection", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("close after incomplete-tail sync uncertainty: %v", err)
	}

	recovered, err := Open(path)
	if err != nil {
		t.Fatalf("reopen and repair incomplete CLEANED tail: %v", err)
	}
	pending, err := recovered.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].LifecycleID != lifecycleID ||
		!pending[0].Created || pending[0].Cleaned ||
		pending[0].ContainerID != testContainerID {
		t.Fatalf("incomplete CLEANED tail must preserve prior CREATED evidence: %+v", pending)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}

	// A fresh owner may now append a complete transition after recovery.
	recovered, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := recovered.Cleaned(lifecycleID); err != nil {
		t.Fatalf("append CLEANED after incomplete-tail recovery: %v", err)
	}
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer final.Close()
	pending, err = final.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("valid post-recovery CLEANED transition remained pending: %+v", pending)
	}
}


func TestJournalRecoveryRejectsCompleteInvalidTransitionWithoutMutatingJournal(t *testing.T) {
	for _, readOnly := range []bool{false, true} {
		name := "writable"
		if readOnly {
			name = "read-only"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "invalid-transition.jsonl")
			journal, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			lifecycleID, err := journal.Begin(testRunnerID, testExecutionID)
			if err != nil {
				t.Fatal(err)
			}
			if err := journal.Created(lifecycleID, testContainerID); err != nil {
				t.Fatal(err)
			}
			if err := journal.Close(); err != nil {
				t.Fatal(err)
			}

			invalid, err := json.Marshal(Event{
				Version: formatVersion, Sequence: 3, Type: EventCreated,
				LifecycleID: lifecycleID, RunnerInstanceID: testRunnerID,
				ExecutionID: testExecutionID, ContainerID: testContainerID,
				At: time.Now().UTC(),
			})
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := file.Write(append(invalid, '\n')); err != nil {
				t.Fatal(err)
			}
			// Include a partial tail as well: recovery must not truncate it
			// before discovering the earlier complete semantic violation.
			if _, err := file.WriteString("{partial"); err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}

			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if readOnly {
				_, err = OpenReadOnly(path)
			} else {
				_, err = Open(path)
			}
			if err == nil {
				t.Fatal("complete but semantically invalid lifecycle event was accepted")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(after) != string(before) {
				t.Fatal("failed recovery mutated journal bytes")
			}
			if _, statErr := os.Stat(path + ".lock"); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("failed recovery left ownership lock behind: %v", statErr)
			}
		})
	}
}


func TestJournalRejectsDuplicateJSONFieldsWithoutMutatingJournal(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "duplicate-field.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(original), "\n")
	if !strings.Contains(line, "\"sequence\":1") {
		t.Fatal("fixture does not contain the expected sequence field")
	}
	mutated := strings.Replace(line, "\"sequence\":1", "\"sequence\":1,\"sequence\":1", 1) + "\n"
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("duplicate JSON field was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed recovery mutated journal containing duplicate fields")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery left ownership lock behind: %v", err)
	}
}


func TestJournalRejectsEscapedDuplicateJSONFieldNames(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "escaped-duplicate-field.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(content), "\n")
	mutated := strings.Replace(line, `"sequence":1`, `"sequence":1,"sequ\u0065nce":1`, 1) + "\n"
	if mutated == string(content) {
		t.Fatal("fixture did not replace the sequence field")
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("escaped duplicate JSON field name was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed recovery mutated journal containing escaped duplicate fields")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery left ownership lock behind: %v", err)
	}
}


func TestJournalRejectsNonCanonicalJSONFieldNames(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "noncanonical-field.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(content), "\n")
	mutated := strings.Replace(line, `"sequence":1`, `"Sequence":1`, 1) + "\n"
	if mutated == string(content) {
		t.Fatal("fixture did not replace the canonical sequence field")
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := Open(path); err == nil {
		t.Fatal("non-canonical JSON field name was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed recovery mutated journal containing a non-canonical field")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery left ownership lock behind: %v", err)
	}
}


func TestJournalRejectsNonCanonicalJSONEncodingWithoutMutatingJournal(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "noncanonical-json.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(content), "\n")
	if !strings.HasPrefix(line, "{") {
		t.Fatal("fixture is not a JSON object")
	}
	// Whitespace is legal JSON, but the journal writer never emits it.
	mutated := "{ " + strings.TrimPrefix(line, "{") + "\n"
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("non-canonical JSON encoding was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed recovery mutated journal containing non-canonical JSON")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery left ownership lock behind: %v", err)
	}
}


func TestJournalRejectsNonUTCTimestampWithoutMutatingJournal(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "non-utc-timestamp.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSuffix(string(content), "\n")
	if !strings.Contains(line, "\"at\":") || !strings.Contains(line, "Z\"") {
		t.Fatalf("fixture does not contain a UTC timestamp: %s", line)
	}
	mutated := strings.Replace(line, "Z\"", "+00:00\"", 1) + "\n"
	if mutated == string(content) {
		t.Fatal("fixture did not replace the UTC timestamp suffix")
	}
	if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("non-UTC lifecycle timestamp was accepted")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("failed recovery mutated journal containing non-UTC timestamp")
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed recovery left ownership lock behind: %v", err)
	}
}


func TestJournalCloseRetriesAfterSyncFailureWithoutReleasingOwnership(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "close-sync-retry.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected close sync failure")
	calls := 0
	journal.syncFn = func(file *os.File) error {
		calls++
		if calls == 1 {
			return injected
		}
		return file.Sync()
	}

	if err := journal.Close(); !errors.Is(err, injected) {
		t.Fatalf("first close error = %v, want injected sync failure", err)
	}
	if _, err := os.Stat(path + ".lock"); err != nil {
		t.Fatalf("ownership lock must remain after failed close sync: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("retry close after sync failure: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful close retry left ownership lock behind: %v", err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("repeated close after success must be idempotent: %v", err)
	}
}

func TestReleaseLockIsIdempotentAfterLockRemoval(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "journal.lock")
	token, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseLock(path, token); err != nil {
		t.Fatalf("first lock release: %v", err)
	}
	if err := releaseLock(path, token); err != nil {
		t.Fatalf("retry after lock removal: %v", err)
	}
}

func TestJournalCloseRetriesAfterLockOwnershipMismatchWithoutRemovingReplacement(t *testing.T) {
	path := filepath.Join(privateTempDir(t), "close-lock-retry.jsonl")
	journal, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := journal.Begin(testRunnerID, testExecutionID); err != nil {
		t.Fatal(err)
	}

	originalLock, err := os.ReadFile(path + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	replacementLock := []byte(`{"pid":99999,"token":"ffffffffffffffffffffffffffffffff","createdAt":"2026-11-19T00:00:00Z"}`)
	if err := os.WriteFile(path+".lock", replacementLock, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := journal.Close(); err == nil || !strings.Contains(err.Error(), "ownership changed") {
		t.Fatalf("close with replacement lock error = %v, want ownership mismatch", err)
	}
	actualLock, err := os.ReadFile(path + ".lock")
	if err != nil {
		t.Fatalf("replacement owner's lock was removed: %v", err)
	}
	if string(actualLock) != string(replacementLock) {
		t.Fatal("close modified the replacement owner's lock")
	}

	// Restore the original token to model an operator resolving the
	// ownership discrepancy. Close must remember that the journal file
	// is already closed and retry only the lock-release operation.
	if err := os.WriteFile(path+".lock", originalLock, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := journal.Close(); err != nil {
		t.Fatalf("retry close after restoring ownership: %v", err)
	}
	if _, err := os.Stat(path + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("successful close retry left lock behind: %v", err)
	}
}

func TestReleaseLockRetriesDirectorySyncAfterSuccessfulRemoval(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "journal.lock")
	token, err := acquireLock(path)
	if err != nil {
		t.Fatal(err)
	}

	injected := errors.New("injected directory sync failure")
	calls := 0
	syncDir := func(gotDirectory string) error {
		calls++
		if gotDirectory != directory {
			t.Fatalf("sync directory = %q, want %q", gotDirectory, directory)
		}
		if calls == 1 {
			return injected
		}
		return syncDirectory(gotDirectory)
	}

	if err := releaseLockWithSync(path, token, syncDir); !errors.Is(err, injected) {
		t.Fatalf("first release error = %v, want injected directory sync failure", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lock should be removed before failed directory sync: %v", err)
	}

	if err := releaseLockWithSync(path, token, syncDir); err != nil {
		t.Fatalf("retry directory sync after lock removal: %v", err)
	}
	if calls != 2 {
		t.Fatalf("directory sync calls = %d, want 2", calls)
	}
}

func TestReleaseLockRejectsNonCanonicalOwnershipMetadataWithoutRemovingLock(t *testing.T) {
	for _, test := range []struct {
		name string
		mutate func(string) string
	}{
		{
			name: "duplicate token field",
			mutate: func(payload string) string {
				return strings.Replace(payload, `"token":"`, `"token":"00000000000000000000000000000000","token":"`, 1)
			},
		},
		{
			name: "unknown field",
			mutate: func(payload string) string {
				return strings.TrimSuffix(payload, "}") + `, "extra":true}`
			},
		},
		{
			name: "noncanonical whitespace",
			mutate: func(payload string) string {
				return "{ " + strings.TrimPrefix(payload, "{")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(privateTempDir(t), "journal.lock")
			token, err := acquireLock(path)
			if err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mutated := test.mutate(string(original))
			if mutated == string(original) {
				t.Fatal("lock fixture mutation did not change payload")
			}
			if err := os.WriteFile(path, []byte(mutated), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := releaseLock(path, token); err == nil {
				t.Fatal("noncanonical lock ownership metadata was accepted")
			}
			actual, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("malformed lock was removed: %v", err)
			}
			if string(actual) != mutated {
				t.Fatal("failed lock release modified ownership metadata")
			}

			// Restore the exact owner record so the fixture leaves no stale lock.
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := releaseLock(path, token); err != nil {
				t.Fatalf("release after restoring canonical owner record: %v", err)
			}
		})
	}
}

func TestAcquireLockCleansUpAfterDirectorySyncFailure(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "journal.lock")
	injected := errors.New("injected initial directory sync failure")
	calls := 0
	syncDir := func(gotDirectory string) error {
		calls++
		if gotDirectory != directory {
			t.Fatalf("sync directory = %q, want %q", gotDirectory, directory)
		}
		if calls == 1 {
			return injected
		}
		return syncDirectory(gotDirectory)
	}

	token, err := acquireLockWithSync(path, syncDir)
	if token != "" {
		t.Fatalf("failed acquisition returned an ownership token %q", token)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("acquire error = %v, want injected directory sync failure", err)
	}
	if calls != 2 {
		t.Fatalf("directory sync calls = %d, want initial sync plus cleanup sync", calls)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed acquisition left an unreachable lock file: %v", err)
	}

	// A subsequent owner can acquire the path normally after cleanup.
	if _, err := acquireLock(path); err != nil {
		t.Fatalf("acquire after failed-attempt cleanup: %v", err)
	}
	if err := releaseLock(path, mustReadLockToken(t, path)); err != nil {
		t.Fatalf("release subsequent owner lock: %v", err)
	}
}

func mustReadLockToken(t *testing.T, path string) string {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var owner struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &owner); err != nil {
		t.Fatal(err)
	}
	return owner.Token
}

func TestAcquireLockCleansUpAfterFileSyncFailure(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "journal.lock")
	injected := errors.New("injected lock file sync failure")
	dirSyncCalls := 0
	syncDir := func(gotDirectory string) error {
		dirSyncCalls++
		if gotDirectory != directory {
			t.Fatalf("sync directory = %q, want %q", gotDirectory, directory)
		}
		return syncDirectory(gotDirectory)
	}

	token, err := acquireLockWithHooks(path, syncDir, func(*os.File) error {
		return injected
	})
	if token != "" {
		t.Fatalf("failed acquisition returned ownership token %q", token)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("acquire error = %v, want injected file sync failure", err)
	}
	if dirSyncCalls != 1 {
		t.Fatalf("directory sync calls = %d, want one cleanup sync", dirSyncCalls)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed file sync left an unreachable lock: %v", err)
	}

	if _, err := acquireLock(path); err != nil {
		t.Fatalf("acquire after failed file sync cleanup: %v", err)
	}
	if err := releaseLock(path, mustReadLockToken(t, path)); err != nil {
		t.Fatalf("release subsequent owner lock: %v", err)
	}
}

func TestAcquireLockDoesNotRemoveReplacementAfterFileSyncFailure(t *testing.T) {
	directory := privateTempDir(t)
	path := filepath.Join(directory, "journal.lock")
	replacement := []byte("replacement-owner-lock")
	injected := errors.New("injected lock file sync failure")

	token, err := acquireLockWithHooks(path, syncDirectory, func(*os.File) error {
		if err := os.Remove(path); err != nil {
			return err
		}
		if err := os.WriteFile(path, replacement, 0o600); err != nil {
			return err
		}
		return injected
	})
	if token != "" {
		t.Fatalf("failed acquisition returned ownership token %q", token)
	}
	if !errors.Is(err, injected) {
		t.Fatalf("acquire error = %v, want injected file sync failure", err)
	}
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("replacement owner's lock was removed: %v", err)
	}
	if string(actual) != string(replacement) {
		t.Fatalf("replacement lock changed: %q", actual)
	}
}
