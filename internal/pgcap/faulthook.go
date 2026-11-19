//go:build faulthook

package pgcap

// FaultMarker is the server message type on which a build with the tag
// faulthook panics the handler of the connection that received it, to show
// that a fault ends that connection alone. The product build has no such code.
const FaultMarker = '!'

func init() {
	faultHook = func(typ byte) {
		if typ == FaultMarker {
			panic("fault hook: marker message")
		}
	}
}
