package pgcap

import (
	"fmt"
	"time"

	"github.com/Amphoze/supapace/internal/pgwire"
)

// maxAuthMessage is the longest authentication request, the one message the
// relay reads whole.
const maxAuthMessage = 1024

// What the relay does with a message whose header passed.
type action int

const (
	actForward action = iota // stream the body to the client
	actDrop                  // read the body and discard it
	actAuth                  // read the body whole (at most maxAuthMessage), check it, then forward
	actFields                // check the first two bytes of the body, then forward
)

type phase int

const (
	phStartup phase = iota // from accept to the first ReadyForQuery
	phSession              // after it
	phStream               // after a CopyBothResponse, until the next ReadyForQuery
)

// Steps of the one authentication exchange a connection may have.
const (
	stepNone = iota
	stepSASL
	stepContinue
	stepFinal
	stepOK
)

// breach is a server message the class does not allow; its text is the reason
// logged.
type breach string

func (b breach) Error() string { return string(b) }

func breachf(format string, a ...any) error { return breach(fmt.Sprintf(format, a...)) }

// state is the protocol state of one connection, as seen from the server's
// messages. It reads only what a header and the few checked bodies give it.
type state struct {
	c     *Class
	slots *StreamSlots // the slice's places in the stream state
	step  int
	phase phase
	used  int64 // bytes of the current byte window
	// counts of the current window
	params, notices int
	// the stream state's interval
	ivStart time.Time // zero before the first read in the state; read with its monotonic clock
	ivUsed  int64
}

func (s *state) authed() bool { return s.step == stepOK }

// windowed tells whether the byte window applies to the next message.
func (s *state) windowed() bool { return s.phase != phStream && s.c.Window != WindowNone }

// counting tells whether the count caps apply: in the startup, in the stream
// state's intervals, and in the session unless the class has no window.
func (s *state) counting() bool { return s.phase != phSession || s.c.Window != WindowNone }

func (s *state) resetCounts() { s.params, s.notices = 0, 0 }

// header judges a server message from its type and body length alone.
func (s *state) header(typ byte, n int) (action, error) {
	length := int64(n) + 4
	if s.c.MessageBytes > 0 && length > s.c.MessageBytes {
		return 0, breachf("message %q of %d bytes over the cap", typ, length)
	}
	if s.windowed() {
		if s.used+1+length > s.c.WindowBytes {
			return 0, breachf("message %q of %d bytes over what remains of the byte window", typ, length)
		}
		s.used += 1 + length
	}
	if !s.authed() {
		switch typ {
		case 'R':
			if length > maxAuthMessage {
				return 0, breachf("authentication request of %d bytes", length)
			}
			return actAuth, nil
		case 'E':
			return actForward, nil
		case 'N':
			return s.notice()
		}
		return 0, breachf("message %q before authentication-ok", typ)
	}
	switch typ {
	case 'R':
		return 0, breach("authentication request after authentication-ok")
	case 'S':
		if s.counting() {
			if s.params++; s.params > s.c.ParamStatusMax {
				return 0, breach("parameter-status messages over the cap")
			}
		}
	case 'N', 'A':
		return s.notice()
	case 'T':
		return actFields, nil
	case 'W':
		if s.phase == phStream {
			break
		}
		if s.c.Stream == nil {
			return 0, breach("copy-both refused by the class")
		}
		if s.slots == nil || !s.slots.acquire(s.c.Stream.ConnsPerProject) {
			return 0, breach("copy-both over the project's stream connections")
		}
		s.phase, s.ivStart, s.ivUsed = phStream, time.Time{}, 0
		s.resetCounts()
	case 'Z':
		if s.phase == phStream {
			s.slots.release()
			s.resetCounts()
		}
		s.phase = phSession
		if s.c.Window == WindowResponse {
			s.used = 0
			s.resetCounts()
		}
	}
	return actForward, nil
}

func (s *state) notice() (action, error) {
	if s.counting() && s.c.NoticesMax > 0 {
		if s.notices++; s.notices > s.c.NoticesMax {
			return 0, breach("notices over the cap")
		}
	}
	if s.c.DropNotices {
		return actDrop, nil
	}
	return actForward, nil
}

// auth checks an authentication request's body: SASL, SASL-continue within the
// iteration floor and cap, SASL-final and authentication-ok, each once and in
// that order.
func (s *state) auth(body []byte) error {
	sub, err := pgwire.AuthSubtype(body)
	if err != nil {
		return breach("malformed authentication request")
	}
	switch {
	case sub == pgwire.AuthSASL && s.step == stepNone:
		s.step = stepSASL
	case sub == pgwire.AuthSASLContinue && s.step == stepSASL:
		it, err := pgwire.ScramIterations(body[4:])
		if err != nil {
			return breach("malformed SCRAM challenge")
		}
		if it < s.c.ScramIterMin || it > s.c.ScramIterMax {
			return breachf("SCRAM iteration count %d outside the class's floor and cap", it)
		}
		s.step = stepContinue
	case sub == pgwire.AuthSASLFinal && s.step == stepContinue:
		s.step = stepFinal
	case sub == pgwire.AuthOK && s.step == stepFinal:
		s.step = stepOK
	default:
		return breachf("authentication request %d refused after step %d", sub, s.step)
	}
	return nil
}

// rowFields checks one row description's field count against the cap: per
// message, wherever the count caps apply.
func (s *state) rowFields(first2 []byte) error {
	f, err := pgwire.RowFields(first2)
	if err != nil {
		return breach("malformed row description")
	}
	if s.counting() && f > s.c.RowFieldsMax {
		return breach("row description fields over the cap")
	}
	return nil
}
