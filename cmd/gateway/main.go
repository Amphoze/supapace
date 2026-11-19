// Command gateway is the node's public entry point: HTTPS on :8443, a
// redirect to HTTPS on :8080, routes and TLS files read from
// /etc/supapace/gateway (mounted read-only). SIGTERM or SIGINT stops it
// gracefully: requests in flight get up to 10 s, then it exits 0. A second
// signal during that grace ends the process at once.
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Amphoze/supapace/internal/gateway"
)

const dir = "/etc/supapace/gateway"

func main() {
	log.SetFlags(log.LstdFlags | log.LUTC)
	g, c, err := start(context.Background(), dir)
	if err != nil {
		log.Fatalf("gateway: tls: %v", err)
	}
	lim := gateway.NewLimiter(gateway.MaxConns, gateway.MaxConnsPerSource)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	tlsLn, plainLn, err := listeners(lim, ":8443", ":8080")
	if err != nil {
		log.Fatalf("gateway: %v", err)
	}
	if err := run(ctx, stop, 10*time.Second, g, c, tlsLn, plainLn); err != nil {
		log.Fatalf("gateway: %v", err)
	}
}

// start reads the gateway directory: the first TLS pair (an error, on which
// the process exits), the route table and, with dash/domain, the dashboard's
// files, which never stop the gateway. Both tables are watched until ctx ends.
func start(ctx context.Context, dir string) (*gateway.Gateway, tls.Certificate, error) {
	// ponytail: the certificates are read once; a renewed one takes a container restart.
	c, err := tls.LoadX509KeyPair(filepath.Join(dir, "tls", "cert.pem"), filepath.Join(dir, "tls", "key.pem"))
	if err != nil {
		return nil, c, err
	}
	tbl := gateway.NewTable(filepath.Join(dir, "routes.json"))
	if err := tbl.Reload(); err != nil {
		log.Printf("gateway: no route table yet (503 until one is read): %v", err)
	}
	go tbl.Watch(ctx, time.Second)
	g := gateway.New(tbl)
	if d := gateway.LoadDashboard(dir); d != nil {
		if err := d.Reload(); err != nil {
			log.Printf("gateway: no dashboard table yet (503 until one is read): %v", err)
		}
		go d.Watch(ctx, time.Second)
		g.SetDashboard(d)
	}
	return g, c, nil
}

// listeners opens the HTTPS and the plain listener, both behind lim.
func listeners(lim *gateway.Limiter, tlsAddr, plainAddr string) (tlsLn, plainLn net.Listener, err error) {
	if tlsLn, err = net.Listen("tcp", tlsAddr); err != nil {
		return nil, nil, err
	}
	if plainLn, err = net.Listen("tcp", plainAddr); err != nil {
		tlsLn.Close()
		return nil, nil, err
	}
	return lim.Listen(tlsLn), lim.Listen(plainLn), nil
}

// run serves h over TLS on tlsLn and the HTTPS redirect on plainLn until ctx
// is done. It then calls stop at once, so a second signal ends the process,
// and gives the requests in flight up to grace. When either server fails, both
// are closed and its error is returned.
func run(ctx context.Context, stop func(), grace time.Duration, h http.Handler, c tls.Certificate,
	tlsLn, plainLn net.Listener) error {
	https := gateway.NewServer(h)
	https.TLSConfig.Certificates = []tls.Certificate{c}
	if g, ok := h.(*gateway.Gateway); ok {
		https.TLSConfig.GetCertificate = g.Certificate // the studio pair by server name
	}
	plain := gateway.NewServer(gateway.Redirect())
	errc := make(chan error, 2)
	go func() { errc <- https.ServeTLS(tlsLn, "", "") }()
	go func() { errc <- plain.Serve(plainLn) }()
	select {
	case err := <-errc:
		https.Close() // one server failed: the other stops too
		plain.Close()
		return err
	case <-ctx.Done():
	}
	stop()
	if err := gateway.Shutdown(grace, https, plain); err != nil {
		log.Printf("gateway: shutdown: %v", err)
	}
	return nil
}
