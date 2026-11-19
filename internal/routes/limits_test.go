package routes

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// sampleBytes is the encoding of sample() before a route entry could carry
// an audience list or a rate, and a file an idle period.
const sampleBytes = `{"generation":17,"domain":"sp.test","projects":{"abcdefghij0123456789":{"state":"active","rest":"http://10.212.0.30:3000","user_roles":["authenticated"],"keys":[{"kid":"k1","class":"anon","kty":"RSA","n":"nnn","e":"AQAB"},{"kid":"k2","class":"service_role","kty":"RSA","n":"nnn","e":"AQAB"},{"kid":"k3","class":"issuer","kty":"RSA","n":"nnn","e":"AQAB"}]}}}`

func TestRoutes_MarshalWithoutNewMembersIsByteIdentical(t *testing.T) {
	b, err := sample().Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != sampleBytes {
		t.Fatalf("encoding changed:\n got %s\nwant %s", b, sampleBytes)
	}
	f, err := Parse([]byte(sampleBytes))
	if err != nil || !reflect.DeepEqual(f, sample()) {
		t.Fatalf("Parse: %+v, %v", f, err)
	}
	// Control: the members, when set, are encoded and survive a round trip.
	g := sample()
	p := g.Projects[refA]
	p.Aud, p.Rate = []string{"app"}, &Rate{RPS: 5, Burst: 10}
	g.Projects[refA], g.IdleStopS = p, 600
	b, err = g.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{`"aud":["app"]`, `"rate":{"rps":5,"burst":10}`, `"idle_stop_s":600`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("%s not in %s", s, b)
		}
	}
	if back, err := Parse(b); err != nil || !reflect.DeepEqual(back, g) {
		t.Errorf("round trip: %+v, %v", back, err)
	}
}

func TestRoutes_NewStatesNeedAnUpstream(t *testing.T) {
	for _, st := range []string{"active", "draining", "asleep", "stopped"} {
		f := sample()
		p := f.Projects[refA]
		p.State = st
		f.Projects[refA] = p
		if _, err := f.Marshal(); err != nil {
			t.Errorf("%s: %v", st, err)
		}
		p.Rest = ""
		f.Projects[refA] = p
		if _, err := f.Marshal(); err == nil {
			t.Errorf("%s without rest accepted", st)
		}
	}
	f := sample()
	p := f.Projects[refA]
	p.State = "paused"
	f.Projects[refA] = p
	if _, err := f.Marshal(); err == nil {
		t.Error("state paused accepted")
	}
}

func TestRoutes_RateAndAudBounds(t *testing.T) {
	long := strings.Repeat("a", 255)
	cases := []struct {
		name string
		aud  []string
		rate *Rate
		idle int
		ok   bool
	}{
		{"none", nil, nil, 0, true},
		{"eight audiences", []string{"1", "2", "3", "4", "5", "6", "7", long}, nil, 0, true},
		{"nine audiences", []string{"1", "2", "3", "4", "5", "6", "7", "8", "9"}, nil, 0, false},
		{"empty audience", []string{""}, nil, 0, false},
		{"audience of 256", []string{long + "a"}, nil, 0, false},
		{"audience with a control byte", []string{"a\nb"}, nil, 0, false},
		{"audience with a high byte", []string{"\xc3\xa9"}, nil, 0, false},
		{"audience with a space", []string{"a b"}, nil, 0, true},
		{"rate 1/1", nil, &Rate{RPS: 1, Burst: 1}, 0, true},
		{"rate max", nil, &Rate{RPS: 100000, Burst: 1000000}, 0, true},
		{"rps 0", nil, &Rate{RPS: 0, Burst: 1}, 0, false},
		{"rps 0, burst 0", nil, &Rate{RPS: 0, Burst: 0}, 0, false},
		{"rps over", nil, &Rate{RPS: 100001, Burst: 100001}, 0, false},
		{"burst below rps", nil, &Rate{RPS: 10, Burst: 9}, 0, false},
		{"burst over 10x", nil, &Rate{RPS: 10, Burst: 101}, 0, false},
		{"burst 10x", nil, &Rate{RPS: 10, Burst: 100}, 0, true},
		{"negative rate", nil, &Rate{RPS: -1, Burst: -1}, 0, false},
		{"idle period", nil, nil, 3600, true},
		{"negative idle period", nil, nil, -1, false},
	}
	for _, c := range cases {
		f := sample()
		p := f.Projects[refA]
		p.Aud, p.Rate = c.aud, c.rate
		f.Projects[refA], f.IdleStopS = p, c.idle
		b, err := f.Marshal()
		if (err == nil) != c.ok {
			t.Errorf("%s: Marshal err %v, want ok %v", c.name, err, c.ok)
		}
		if !c.ok { // Parse refuses what Marshal refuses
			raw := strings.Replace(sampleBytes, `"state":"active"`, `"state":"active",`+member(c.aud, c.rate), 1)
			if c.idle != 0 {
				raw = strings.Replace(sampleBytes, `"generation":17`, `"generation":17,"idle_stop_s":-1`, 1)
			}
			if _, err := Parse([]byte(raw)); err == nil {
				t.Errorf("%s: Parse accepted %s", c.name, raw)
			}
		} else if back, err := Parse(b); err != nil || !reflect.DeepEqual(back, f) {
			t.Errorf("%s: round trip %+v, %v", c.name, back, err)
		}
	}
	// A rate member must name both figures: a missing one is zero, refused.
	raw := strings.Replace(sampleBytes, `"state":"active"`, `"state":"active","rate":{"rps":5}`, 1)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Error("rate without burst accepted")
	}
}

// member renders the aud or rate member for a raw file.
func member(aud []string, r *Rate) string {
	if r != nil {
		return `"rate":{"rps":` + strconv.Itoa(r.RPS) + `,"burst":` + strconv.Itoa(r.Burst) + `}`
	}
	var q []string
	for _, a := range aud {
		q = append(q, strconv.Quote(a))
	}
	return `"aud":[` + strings.Join(q, ",") + `]`
}
