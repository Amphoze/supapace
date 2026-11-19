package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

const holdTestDays = 8 * 24 * time.Hour

// holdSet sets the slice hold for one test.
func holdSet(t *testing.T, s *Store, d time.Duration) {
	s.SetSliceHold(d)
	t.Cleanup(func() { s.SetSliceHold(0) })
}

// holdPurge takes an active project through delete to purged.
func holdPurge(t *testing.T, s *Store, r string) {
	t.Helper()
	markDeleted(t, s, r)
	must(t, s.MarkPurged(context.Background(), r))
}

// holdRow is the hold of index i, and whether there is one.
func holdRow(t *testing.T, s *Store, i int) (time.Time, bool) {
	t.Helper()
	var at time.Time
	err := s.pool.QueryRow(context.Background(), "select free_after from slice_hold where subnet_index = $1", i).Scan(&at)
	if err != nil {
		return at, false
	}
	return at, true
}

func TestPlace_PurgedSliceHeldThenReused(t *testing.T) {
	ctx := context.Background()
	t.Run("one slice", func(t *testing.T) {
		c := testConfig()
		c.ProjectBlock = "10.213.0.0/26" // one slice
		s := newStore(t, c)
		holdSet(t, s, holdTestDays)
		a := newActive(t, s, 1)
		holdPurge(t, s, a)
		at, ok := holdRow(t, s, 0)
		if !ok {
			t.Fatal("the purge held nothing")
		}
		memberNear(t, "free_after", at, memberDBNow(t, s).Add(holdTestDays), 30*time.Second)
		mustCreate(t, s, ref(2))
		_, err := s.Place(ctx, ref(2))
		want := "no free slice; 1 held until " + at.UTC().Format(time.RFC3339)
		if !errors.Is(err, ErrNodeFull) || !strings.Contains(err.Error(), want) {
			t.Fatalf("Place inside the hold: %v, want %q", err, want)
		}
		// Once the window has passed the slice is given again, and the row goes.
		sqlExec(t, s, "update slice_hold set free_after = now() - interval '1 second'")
		if p := mustPlace(t, s, ref(2)); p.SubnetIndex != 0 {
			t.Fatalf("slice %d after the hold", p.SubnetIndex)
		}
		if _, ok := holdRow(t, s, 0); ok {
			t.Fatal("a passed hold was kept")
		}
	})
	t.Run("next index; survives a new store; later time kept", func(t *testing.T) {
		s := newStore(t, testConfig())
		holdSet(t, s, holdTestDays)
		a := newActive(t, s, 1)
		newActive(t, s, 2)
		holdPurge(t, s, a)
		mustCreate(t, s, ref(3))
		if p := mustPlace(t, s, ref(3)); p.SubnetIndex != 2 {
			t.Fatalf("slice %d inside the hold, want the next index 2", p.SubnetIndex)
		}
		s2, err := Open(ctx, sockDir)
		must(t, err)
		defer s2.Close()
		mustCreate(t, s2, ref(4))
		if p := mustPlace(t, s2, ref(4)); p.SubnetIndex != 3 {
			t.Fatalf("slice %d from a new store, want 3", p.SubnetIndex)
		}
		// A second purge of the same index keeps the later time.
		sqlExec(t, s, "delete from slice_hold")
		e := newActive(t, s, 5)
		if p, _ := s.GetProject(ctx, e); *p.SubnetIndex != 0 {
			t.Fatalf("slice %d", *p.SubnetIndex)
		}
		later := memberDBNow(t, s).Add(30 * 24 * time.Hour)
		sqlExec(t, s, "insert into slice_hold select id, 0, $1 from node", later)
		holdPurge(t, s, e)
		if at, _ := holdRow(t, s, 0); !at.Equal(later) {
			t.Fatalf("free_after %v, want the later %v", at, later)
		}
		// And an earlier stored time is moved to the purge's.
		f := ref(6)
		mustCreate(t, s, f)
		sqlExec(t, s, "update slice_hold set free_after = now() - interval '1 second'")
		if p := mustPlace(t, s, f); p.SubnetIndex != 0 {
			t.Fatalf("slice %d", p.SubnetIndex)
		}
		sqlExec(t, s, "insert into slice_hold select id, 0, now() + interval '1 day' from node")
		activate(t, s, f, holdCreateOp(t, s, f))
		holdPurge(t, s, f)
		at, _ := holdRow(t, s, 0)
		memberNear(t, "free_after", at, memberDBNow(t, s).Add(holdTestDays), 30*time.Second)
	})
	t.Run("controls: no hold, and an abort", func(t *testing.T) {
		s := newStore(t, testConfig())
		a := newActive(t, s, 1)
		holdPurge(t, s, a)
		mustCreate(t, s, ref(2))
		if p := mustPlace(t, s, ref(2)); p.SubnetIndex != 0 {
			t.Fatalf("with no hold the purged slice was not reused: %d", p.SubnetIndex)
		}
		holdSet(t, s, holdTestDays)
		mustCreate(t, s, ref(3))
		if p := mustPlace(t, s, ref(3)); p.SubnetIndex != 1 {
			t.Fatalf("slice %d", p.SubnetIndex)
		}
		must(t, s.MarkAborted(ctx, ref(3)))
		mustCreate(t, s, ref(4))
		if p := mustPlace(t, s, ref(4)); p.SubnetIndex != 1 {
			t.Fatalf("a slice freed by an abort was held: %d", p.SubnetIndex)
		}
		if n := count(t, s, "select count(*) from slice_hold"); n != 0 {
			t.Fatalf("%d holds", n)
		}
	})
}

// holdCreateOp is the id of r's create operation.
func holdCreateOp(t *testing.T, s *Store, r string) int64 {
	t.Helper()
	return int64(count(t, s, "select id from operation where ref = $1 and kind = 'create'", r))
}
