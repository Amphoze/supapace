//go:build reach

package reach

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	t17Fn   = "/rest/v1/rpc/reach_t17"
	t17HTML = "/rest/v1/rpc/reach_t17_html"
	t17Page = "<!doctype html><title>reach</title><p id=x>sandboxed</p>"
)

// t17SQL creates two functions in a project that set response.headers from
// their argument: one returning text, one declared with a text/html media-type
// handler so PostgREST returns its result verbatim.
var t17SQL = `drop function if exists public.reach_t17(text), public.reach_t17_html(text);
drop domain if exists public."text/html";
create domain public."text/html" as text;
create function public.reach_t17(h text) returns text language plpgsql as $$
begin perform set_config('response.headers', h, true); return 'reach'; end $$;
create function public.reach_t17_html(h text) returns public."text/html" language plpgsql as $$
begin perform set_config('response.headers', h, true); return '` + t17Page + `'; end $$;
grant execute on function public.reach_t17(text), public.reach_t17_html(text) to anon;
notify pgrst, 'reload schema';`

const t17Drop = `drop function if exists public.reach_t17(text), public.reach_t17_html(text);
drop domain if exists public."text/html";
notify pgrst, 'reload schema';`

// headerArg is the response.headers value for the given name, value pairs.
func headerArg(t testing.TB, kv ...string) []byte {
	t.Helper()
	var hs []map[string]string
	for i := 0; i+1 < len(kv); i += 2 {
		hs = append(hs, map[string]string{kv[i]: kv[i+1]})
	}
	h, _ := json.Marshal(hs)
	b, _ := json.Marshal(map[string]string{"h": string(h)})
	return b
}

// wantSandbox requires exactly the gateway's two sandbox headers.
func wantSandbox(t testing.TB, what string, resp *http.Response) {
	t.Helper()
	if csp, xcto := resp.Header.Values("Content-Security-Policy"), resp.Header.Values("X-Content-Type-Options"); !slices.Equal(csp, []string{"sandbox"}) || !slices.Equal(xcto, []string{"nosniff"}) {
		t.Errorf("%s: Content-Security-Policy %q, X-Content-Type-Options %q; want exactly sandbox and nosniff", what, csp, xcto)
	}
}

// TestReach17_UpstreamResponses: what a tenant's function can put in a
// response does not reach the client unfiltered — no Domain cookie, no
// Set-Cookie2 or Clear-Site-Data, no Server header, the sandbox headers on every
// response whatever the upstream set, a 502 for an oversized upstream header
// while another project is served — and the published ports listen on IPv4
// only. Each refusal follows its accepted twin on the same path.
func TestReach17_UpstreamResponses(t *testing.T) {
	A, B := fixtureAB(t)
	domain := nodeConf(t).Domain
	t.Cleanup(func() {
		if _, err := sqlAs(t, A, "postgres", t17Drop); err != nil {
			t.Errorf("dropping the test functions: %v", err)
		}
	})
	if _, err := sqlAs(t, A, "postgres", t17SQL); err != nil {
		t.Fatal(err)
	}
	call := func(path string, body []byte, kv ...string) *http.Response {
		t.Helper()
		h := hdr(append([]string{"apikey", A.AnonKey, "Content-Type", "application/json"}, kv...)...)
		return gatewayDo(t, A, "POST", path, h, body)
	}
	// PostgREST reloads its schema cache asynchronously.
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(time.Second) {
		resp := call(t17Fn, headerArg(t, "X-Probe", "ready"))
		if resp.StatusCode == 200 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the test function is not served within 30 s: %s", describe(resp))
		}
	}

	t.Run("set_cookie_domain", func(t *testing.T) {
		// The gateway drops a cookie when any attribute after the first pair is
		// named Domain, in any case and with any spacing or value; the first pair
		// is the cookie itself, so a cookie named Domain is not an attribute.
		for _, c := range []string{"reach=1; Path=/", "Domain=" + domain + "; Path=/"} {
			resp := call(t17Fn, headerArg(t, "Set-Cookie", c))
			if got := resp.Header.Values("Set-Cookie"); resp.StatusCode != 200 || !slices.Equal(got, []string{c}) {
				t.Fatalf("control: the host-only cookie %q: %s, Set-Cookie %q", c, describe(resp), got)
			}
			wantSandbox(t, "control: a host-only cookie", resp)
		}
		for _, c := range []string{
			"reach=1; Domain=" + domain + "; Path=/",
			"reach=1; domain=" + domain,
			"reach=1; DOMAIN=" + domain,
			"reach=1;  Domain = " + domain + " ",
			`reach=1; Domain="` + domain + `"`,
			"reach=1; Domain=." + domain,
			"reach=1; Path=/; Secure; Domain=" + domain,
			"reach=1; Domain",
		} {
			resp := call(t17Fn, headerArg(t, "Set-Cookie", c))
			if got := resp.Header.Values("Set-Cookie"); resp.StatusCode != 200 || len(got) != 0 {
				t.Errorf("the cookie %q: %s, Set-Cookie %q reached the client", c, describe(resp), got)
			}
			wantSandbox(t, "a cookie with a Domain attribute", resp)
		}
	})

	t.Run("server_header", func(t *testing.T) {
		direct, err := directDo(t, A, "POST", "/rpc/reach_t17", hdr("Content-Type", "application/json"), headerArg(t, "X-Probe", "direct"))
		if err != nil || direct.StatusCode != 200 || direct.Header.Get("Server") == "" {
			t.Fatalf("control: PostgREST directly: %s, Server %q; want a Server header from upstream", outcome(direct, err), headerOr(direct, "Server"))
		}
		resp := call(t17Fn, headerArg(t, "X-Probe", "gateway"))
		if resp.StatusCode != 200 || resp.Header.Get("X-Probe") != "gateway" {
			t.Fatalf("control: through the gateway: %s", describe(resp))
		}
		if got := resp.Header.Values("Server"); len(got) != 0 {
			t.Fatalf("Server %q reached the client", got)
		}
	})

	t.Run("upstream_header_bound", func(t *testing.T) {
		small := strings.Repeat("a", 1<<10)
		resp := call(t17Fn, headerArg(t, "X-Reach-Pad", small))
		if resp.StatusCode != 200 || resp.Header.Get("X-Reach-Pad") != small {
			t.Fatalf("control: a 1 KiB upstream header did not arrive whole: %s", describe(resp))
		}
		stop := servedThroughout(t, B)
		resp = call(t17Fn, headerArg(t, "X-Reach-Pad", strings.Repeat("a", 40<<10)))
		wantGatewayRefusal(t, "a 40 KiB upstream header", resp, 502, "upstream_unavailable")
		wantSandbox(t, "the gateway's 502", resp)
		stop()
	})

	t.Run("set_cookie2_and_clear_site_data", func(t *testing.T) {
		resp := call(t17Fn, headerArg(t, "Set-Cookie2", "reach=1", "Clear-Site-Data", `"cookies"`, "X-Probe", "kept"))
		if resp.StatusCode != 200 || resp.Header.Get("X-Probe") != "kept" {
			t.Fatalf("control: X-Probe set beside them did not arrive: %s", describe(resp))
		}
		for _, h := range []string{"Set-Cookie2", "Clear-Site-Data"} {
			if got := resp.Header.Values(h); len(got) != 0 {
				t.Errorf("%s %q reached the client", h, got)
			}
		}
		wantSandbox(t, "Set-Cookie2 and Clear-Site-Data", resp)
	})

	t.Run("html_sandboxed", func(t *testing.T) {
		resp := call(t17HTML, headerArg(t, "Content-Security-Policy", "default-src *", "X-Content-Type-Options", "none"), "Accept", "text/html")
		if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("the HTML function: %s, Content-Type %q", describe(resp), resp.Header.Get("Content-Type"))
		}
		if got := bodyOf(resp); !bytes.Equal(got, []byte(t17Page)) {
			t.Fatalf("control: the body is not the function's result byte for byte (%d bytes, want %d)", len(got), len(t17Page))
		}
		wantSandbox(t, "an HTML body whose upstream set its own CSP and nosniff", resp)
	})

	t.Run("gateway_error_sandboxed", func(t *testing.T) {
		resp := gatewayDo(t, A, "GET", whoamiPath, nil, nil)
		wantGatewayRefusal(t, "no apikey", resp, 401, "no_apikey")
		wantSandbox(t, "the gateway's 401", resp)
	})

	t.Run("published_ipv4_only", func(t *testing.T) {
		ls := nsListeners(t, "")
		for _, port := range []uint16{443, 80} {
			if !slices.Contains(ls, Listener{"tcp", netip.AddrPortFrom(netip.IPv4Unspecified(), port)}) {
				t.Errorf("control: 0.0.0.0:%d is not listed", port)
			}
			for _, l := range ls {
				if l.Proto == "tcp" && l.Addr.Port() == port && l.Addr.Addr().Is6() {
					t.Errorf("an IPv6 listener on port %d: %v", port, l.Addr)
				}
			}
		}
	})
}

func headerOr(resp *http.Response, name string) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get(name)
}

// servedThroughout requests B's whoami() through the gateway every 100 ms until
// the returned function is called (or the test ends: it is also a cleanup);
// that function fails the test unless at least three requests were made and
// every one was answered 200. Calling it again does nothing.
func servedThroughout(t testing.TB, p Project) func() {
	t.Helper()
	conf, dst := gatewayTLS(t, p)
	tr := &http.Transport{TLSClientConfig: conf, DisableKeepAlives: true, DialContext: dialer(netip.Addr{}).DialContext}
	client := &http.Client{Transport: tr, Timeout: 30 * time.Second}
	var mu sync.Mutex
	var n int
	var bad []string
	done, quit := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			req, _ := http.NewRequest("GET", "https://"+dst.String()+whoamiPath, nil)
			req.Host = conf.ServerName
			req.Header.Set("apikey", p.AnonKey)
			resp, err := client.Do(req)
			mu.Lock()
			n++
			switch {
			case err != nil:
				bad = append(bad, errText(err))
			case resp.StatusCode != 200:
				bad = append(bad, fmt.Sprintf("status %d", resp.StatusCode))
			}
			mu.Unlock()
			if resp != nil {
				resp.Body.Close()
			}
			select {
			case <-quit:
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	var once sync.Once
	stop := func() {
		once.Do(func() {
			time.Sleep(time.Second) // and a moment after
			close(quit)
			<-done
			tr.CloseIdleConnections()
			if n < 3 || len(bad) > 0 {
				t.Errorf("project %s while the other's upstream misbehaved: %d requests, failures %q", p.Ref, n, bad)
			}
		})
	}
	t.Cleanup(stop)
	return stop
}

// directDo sends one request straight to p's PostgREST at its platform address
// from the gateway's network namespace (the node has no path to the platform
// bridge) and reads the whole response.
func directDo(t testing.TB, p Project, method, path string, h http.Header, body []byte) (*http.Response, error) {
	t.Helper()
	pid, _ := containerPid(t, gatewayName)
	addr := netip.AddrPortFrom(nodeConf(t).PlatformAddr(p.SubnetIndex), 3000).String()
	var c net.Conn
	var dialErr error
	if err := inNetns(pid, func() { c, dialErr = net.DialTimeout("tcp", addr, 5*time.Second) }); err != nil {
		t.Fatalf("entering the gateway's network namespace: %v", err)
	}
	if dialErr != nil {
		return nil, dialErr
	}
	defer c.Close()
	req := newRequest(t, addr, method, path, h, body)
	c.SetDeadline(time.Now().Add(httpTimeout))
	if err := req.Write(c); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), req)
	if err != nil {
		return nil, err
	}
	return resp, buffer(resp)
}
