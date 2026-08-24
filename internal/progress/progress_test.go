package progress

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// Unarmed, every hook must cost a nil check and nothing else. This is what lets
// the Go lowerer call Advance once per function on a scan nobody is watching.
func TestDisabledIsANoOp(t *testing.T) {
	if s := Start("x", "x", 10, "files"); s != nil {
		t.Fatalf("Start returned %v with the registry unarmed, want nil", s)
	}
	var nilStage *Stage
	nilStage.Advance(1)
	nilStage.Done(nil)
	nilStage.Done(errors.New("boom"))
	if got := Stages(); len(got) != 0 {
		t.Errorf("Stages = %v with the registry unarmed, want empty", got)
	}
}

// Advance is the one hot write; it must total exactly under -race.
func TestAdvanceIsExactUnderConcurrency(t *testing.T) {
	defer Enable()()
	s := Start("lower", "go lowering", 4000, "funcs")

	const workers, each = 8, 500
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				s.Advance(1)
			}
		}()
	}
	wg.Wait()

	got := Stages()
	if len(got) != 1 {
		t.Fatalf("stages = %d, want 1", len(got))
	}
	if got[0].Done != workers*each {
		t.Errorf("Done = %d, want %d", got[0].Done, workers*each)
	}
}

func TestLedgerRecordsOutcomeAndOrder(t *testing.T) {
	defer Enable()()
	first := Start("walk", "walk", 0, "")
	second := Start("py", "python parse & lower", 12, "files")
	second.Advance(5)
	first.Done(nil)
	second.Done(errors.New("python3 not found"))

	got := Stages()
	if len(got) != 2 {
		t.Fatalf("stages = %d, want 2", len(got))
	}
	// Registration order, not completion order: the display reads top to bottom.
	if got[0].ID != "walk" || got[1].ID != "py" {
		t.Errorf("order = %q,%q, want walk,py", got[0].ID, got[1].ID)
	}
	if got[0].Failed {
		t.Error("walk succeeded but is marked failed")
	}
	// A frontend that failed after doing work is exactly what a watcher needs to
	// see, so a failed stage keeps its counts and stays in the ledger.
	if !got[1].Failed || got[1].Done != 5 || got[1].Total != 12 {
		t.Errorf("failed stage = %+v, want Failed with 5/12", got[1])
	}
	for _, s := range got {
		if s.Running {
			t.Errorf("%s still Running after Done", s.ID)
		}
	}
}

// Elapsed has to keep moving while a stage runs, and freeze once it stops —
// that is the whole reason the display can tick with no events arriving.
func TestElapsedRunsLiveAndThenFreezes(t *testing.T) {
	clock := time.Unix(0, 0)
	now = func() time.Time { return clock }
	defer func() { now = time.Now }()

	defer Enable()()
	s := Start("load", "go parse & typecheck", 0, "")

	clock = clock.Add(300 * time.Millisecond)
	if got := Stages()[0]; got.Elapsed != 300*time.Millisecond || !got.Running {
		t.Errorf("running stage = %v elapsed, Running=%v; want 300ms, true", got.Elapsed, got.Running)
	}

	s.Done(nil)
	clock = clock.Add(5 * time.Second)
	if got := Stages()[0]; got.Elapsed != 300*time.Millisecond {
		t.Errorf("finished stage elapsed = %v, want it frozen at 300ms", got.Elapsed)
	}
}

// Two overlapping scans would interleave into one meaningless ledger.
func TestSecondEnableDoesNotResetTheLedger(t *testing.T) {
	disable := Enable()
	defer disable()
	Start("walk", "walk", 0, "")

	inner := Enable()
	if got := Stages(); len(got) != 1 {
		t.Errorf("a nested Enable discarded the ledger: %d stages, want 1", len(got))
	}
	inner() // the no-op disable must not disarm the outer scan
	if Start("second", "second", 0, "") == nil {
		t.Error("the nested disable disarmed the outer scan's registry")
	}
}

// Disarming stops registration but leaves the ledger readable, so the display
// can draw its final summary after Scan has returned.
func TestDisableKeepsTheLedgerReadable(t *testing.T) {
	disable := Enable()
	Start("walk", "walk", 0, "").Done(nil)
	disable()

	if got := Stages(); len(got) != 1 {
		t.Errorf("stages after disable = %d, want the ledger kept", len(got))
	}
	if Start("late", "late", 0, "") != nil {
		t.Error("Start registered a stage after disable")
	}
}

// Offset is measured from the moment the ledger was armed, so a display can say
// where a stage sat in the run without quantising it to its own frame clock.
func TestOffsetIsMeasuredFromArming(t *testing.T) {
	clock := time.Unix(0, 0)
	saved := now
	now = func() time.Time { return clock }
	defer func() { now = saved }()

	defer Enable()()
	clock = clock.Add(2 * time.Second)
	s := Start("taint", "taint propagation", 3, "rules")
	clock = clock.Add(400 * time.Millisecond)
	s.Done(nil)

	got := Stages()[0]
	if got.Offset != 2*time.Second {
		t.Errorf("Offset = %v, want 2s", got.Offset)
	}
	if got.Elapsed != 400*time.Millisecond {
		t.Errorf("Elapsed = %v, want 400ms", got.Elapsed)
	}
	if got.Unit != "rules" {
		t.Errorf("Unit = %q, want %q", got.Unit, "rules")
	}
}
