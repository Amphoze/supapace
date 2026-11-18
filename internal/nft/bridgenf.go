package nft

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// procSys is the sysctl tree of this process's network namespace (a temporary
// directory in tests).
var procSys = "/proc/sys"

// The switches that divert bridged frames into the routed chains when the
// br_netfilter module is loaded. They exist only while it is.
var bridgeNFKeys = []string{"bridge-nf-call-iptables", "bridge-nf-call-ip6tables", "bridge-nf-call-arptables"}

func bridgeNFPath(k string) string { return filepath.Join(procSys, "net", "bridge", k) }

// EnsureBridgeNF writes 0 to every bridge-nf-call switch present in this
// process's network namespace. A switch that is absent (the module is not
// loaded) needs nothing and is never created.
func EnsureBridgeNF() error {
	var errs []error
	for _, k := range bridgeNFKeys {
		f, err := os.OpenFile(bridgeNFPath(k), os.O_WRONLY|os.O_TRUNC, 0)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err == nil {
			_, err = f.WriteString("0\n")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("nft: switching off %s: %w", k, err))
		}
	}
	return errors.Join(errs...)
}

// checkBridgeNF returns ErrBridgeNF unless every switch present reads 0.
func checkBridgeNF() error {
	for _, k := range bridgeNFKeys {
		b, err := os.ReadFile(bridgeNFPath(k))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("%w: reading %s: %v", ErrBridgeNF, k, err)
		}
		if v := strings.TrimSpace(string(b)); v != "0" {
			return fmt.Errorf("%w: %s = %q", ErrBridgeNF, k, v)
		}
	}
	return nil
}
