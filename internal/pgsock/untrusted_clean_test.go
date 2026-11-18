package pgsock

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const rawMark = "RAW\x1b[31m\u202e"

var cleanSentinels = []error{ErrNotSocket, ErrPeer, ErrCleartextRequested, ErrNotScram, ErrScramParams,
	ErrBudget, ErrEnvironment, context.DeadlineExceeded, context.Canceled}

type panicErr struct{}

func (panicErr) Error() string { panic("boom") }

// walk visits every error reachable by Unwrap from err.
func walk(err error, visit func(error)) {
	if err == nil {
		return
	}
	visit(err)
	switch u := err.(type) {
	case interface{ Unwrap() error }:
		walk(u.Unwrap(), visit)
	case interface{ Unwrap() []error }:
		for _, e := range u.Unwrap() {
			walk(e, visit)
		}
	}
}

func TestUntrusted_CleanAttack(t *testing.T) {
	pe := &pgconn.PgError{Code: "42P01", Message: "m" + rawMark, Detail: rawMark, Hint: rawMark, Where: rawMark}
	inputs := map[string]error{
		"plain":            errors.New("plain " + rawMark),
		"server":           pe,
		"server wrapped":   fmt.Errorf("w %s: %w", rawMark, pe),
		"joined":           errors.Join(errors.New(rawMark), pe, ErrBudget),
		"scan error":       pgx.ScanArgError{ColumnIndex: 0, FieldName: rawMark, Err: errors.New(rawMark)},
		"net error":        &net.OpError{Op: "read", Net: "unix", Err: fmt.Errorf("%s: %w", rawMark, os.ErrDeadlineExceeded)},
		"path error":       &fs.PathError{Op: "open", Path: rawMark, Err: fs.ErrNotExist},
		"deadline":         fmt.Errorf("%s: %w", rawMark, context.DeadlineExceeded),
		"canceled+peer":    errors.Join(context.Canceled, fmt.Errorf("%s: %w", rawMark, ErrPeer)),
		"huge":             errors.New(strings.Repeat("x", 1<<20) + rawMark),
		"server error own": &ServerError{Code: "bad\x1b", Message: rawMark},
	}
	for name, in := range inputs {
		t.Run(name, func(t *testing.T) {
			cl := Clean(in)
			if Clean(cl) != cl {
				t.Fatal("not idempotent")
			}
			if again := Clean(fmt.Errorf("x: %w", cl)); again.Error() != Sanitize("x: "+cl.Error(), 512) {
				t.Fatalf("re-clean of a wrapped clean error: %q", again)
			}
			// nothing reachable but the clean error, a *ServerError and sentinels
			walk(cl, func(e error) {
				switch e.(type) {
				case *cleanError, *ServerError:
					return
				}
				for _, s := range cleanSentinels {
					if e == s {
						return
					}
				}
				t.Fatalf("reachable through Unwrap: %T %q", e, e)
			})
			for _, target := range []any{new(*pgconn.PgError), new(pgx.ScanArgError), new(*net.OpError), new(*fs.PathError), new(*pgconn.ConnectError)} {
				if errors.As(cl, target) {
					t.Fatalf("errors.As to %T succeeded", target)
				}
			}
			var se *ServerError
			_, hadPg := in.(*pgconn.PgError)
			var pe2 *pgconn.PgError
			var se2 *ServerError
			hadServer := hadPg || errors.As(in, &pe2) || errors.As(in, &se2)
			if errors.As(cl, &se) != hadServer {
				t.Fatalf("*ServerError exposed %v, server error held %v", !hadServer, hadServer)
			}
			if se != nil {
				assertClean(t, se.Message)
				if se.Code != "" && !sqlstateRE.MatchString(se.Code) {
					t.Fatalf("code %q", se.Code)
				}
			}
			for _, s := range cleanSentinels {
				if errors.Is(cl, s) != errors.Is(in, s) {
					t.Fatalf("sentinel %v: clean %v, original %v", s, errors.Is(cl, s), errors.Is(in, s))
				}
			}
			if errors.Is(cl, in) {
				t.Fatal("matches the original")
			}
			var buf bytes.Buffer
			slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "err", cl)
			slog.New(slog.NewTextHandler(&buf, nil)).Info("x", "err", cl)
			jb, _ := json.Marshal(cl)
			outs := []string{buf.String(), string(jb)}
			for _, v := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
				outs = append(outs, fmt.Sprintf(v, cl))
			}
			for _, o := range outs {
				if strings.Contains(o, "\x1b") || strings.Contains(o, "\u202e") || strings.Contains(o, `\x1b`) || strings.Contains(o, `\u202e`) {
					t.Fatalf("raw text in %q", o)
				}
			}
			if len(cl.Error()) > 512 {
				t.Fatalf("text of %d bytes", len(cl.Error()))
			}
			row("clean %s: %q; %#v", name, cl.Error()[:min(len(cl.Error()), 80)], cl)
		})
	}
	t.Run("nil", func(t *testing.T) {
		if Clean(nil) != nil {
			t.Fatal("nil")
		}
	})
	t.Run("panicking Error", func(t *testing.T) {
		defer func() { row("clean of an error whose Error panics: recovered %v", recover()) }()
		Clean(panicErr{})
	})
}

type embeds struct {
	Target
	Extra int
}
type embedsPtr struct {
	*Target
	Extra int
}
type nested struct {
	Inner struct{ T Target }
	Ptr   *Target
}

func TestUntrusted_MarshalJSONPositions(t *testing.T) {
	tg := Target{Ref: testRef, User: testUser, Password: testPassword, ScramSalt: testSalt()}
	salt := fmt.Sprint(testSalt())
	check := func(name string, v any) {
		b, err := func() (b []byte, err error) {
			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("panic: %v", r)
				}
			}()
			return json.Marshal(v)
		}()
		s := string(b)
		row("json %s: %s err %v", name, s, err)
		if strings.Contains(s, testPassword) || strings.Contains(s, salt) || strings.Contains(s, "ScramSalt\":\"") && !strings.Contains(s, "redacted") {
			t.Errorf("%s leaks: %s", name, s)
		}
	}
	nt := nested{Ptr: &tg}
	nt.Inner.T = tg
	check("value", tg)
	check("pointer", &tg)
	check("slice", []Target{tg})
	check("map", map[string]*Target{"a": &tg})
	check("nested", nt)
	check("embedded", embeds{tg, 7})
	check("embedded pointer", embedsPtr{&tg, 7})
	check("embedded nil pointer", embedsPtr{nil, 7})
	check("nil pointer", (*Target)(nil))
	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("x", "nested", nt, "slice", []Target{tg}, "embedded", embeds{tg, 7})
	if strings.Contains(buf.String(), testPassword) {
		t.Errorf("slog JSON leaks: %s", buf.String())
	}
	// encoders that do not consult MarshalJSON
	var gb bytes.Buffer
	gerr := gob.NewEncoder(&gb).Encode(tg)
	xb, xerr := xml.Marshal(tg)
	row("gob leaks %v (err %v); xml leaks %v (err %v)", bytes.Contains(gb.Bytes(), []byte(testPassword)), gerr,
		bytes.Contains(xb, []byte(testPassword)), xerr)
}
