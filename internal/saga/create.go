package saga

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Amphoze/supapace/internal/agent"
	"github.com/Amphoze/supapace/internal/bootstrap"
	"github.com/Amphoze/supapace/internal/jwtx"
	"github.com/Amphoze/supapace/internal/pgsock"
	"github.com/Amphoze/supapace/internal/secrets"
	"github.com/Amphoze/supapace/internal/store"
)

// Create steps. Step 1 (the project row and this operation) is the admin
// API's; steps 5, 8 and 10 do not exist in this phase.
var createSteps = []step{
	{"2", (*job).createSecrets},
	{"3", (*job).place},
	{"4a", (*job).clusterFirstBoot},
	{"4", (*job).clusterFirstBoot},
	{"6", (*job).putKeys},
	{"7", (*job).mintTokens},
	{"9", (*job).postgrest},
	{"11", (*job).publish},
	{"12", (*job).activate},
}

// Secret names and how each is made. A secret is written once: a present
// row is never generated again.
var secretMakers = []struct {
	name string
	make func() ([]byte, error)
}{
	{"pg.supabase_admin.password", password},
	{"pg.postgres.password", password},
	{"pg.authenticator.password", password},
	{"jwt.anon.private", rsaKey},
	{"jwt.service_role.private", rsaKey},
	{"jwt.secret", func() ([]byte, error) { return random(32) }},
	{"pgsodium.root_key", func() ([]byte, error) {
		b, err := random(32)
		return []byte(hex.EncodeToString(b)), err
	}},
}

// scramRoles are the roles the platform logs in as or sets a password for.
var scramRoles = []string{"supabase_admin", "postgres", "authenticator"}

func random(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	return b, err
}

// password is 32 random bytes, base64url: printable ASCII, as SCRAM needs.
func password() ([]byte, error) {
	b, err := random(32)
	return []byte(base64.RawURLEncoding.EncodeToString(b)), err
}

// rsaKey is an RSA-2048 key, PKCS#8 DER.
func rsaKey() ([]byte, error) {
	k, _, err := jwtx.GenerateKey()
	if err != nil {
		return nil, err
	}
	return x509.MarshalPKCS8PrivateKey(k)
}

// dek returns the project's data key, wrapping and storing a new one when
// none exists (a row already present, live or destroyed, is kept).
func (r *Runner) dek(ctx context.Context, ref string, create bool) ([]byte, error) {
	n, w, err := r.st.GetDEK(ctx, ref)
	if errors.Is(err, store.ErrNotFound) && create {
		dek, err := random(32)
		if err != nil {
			return nil, err
		}
		n, w, err := secrets.WrapDEK(r.kek, ref, dek)
		clear(dek)
		if err != nil {
			return nil, err
		}
		if err := r.st.PutDEK(ctx, ref, kekID, n, w); err != nil {
			return nil, err
		}
		return r.dek(ctx, ref, false) // whichever row won is the key
	}
	if err != nil {
		return nil, err
	}
	return secrets.UnwrapDEK(r.kek, ref, n, w)
}

func (r *Runner) secret(ctx context.Context, dek []byte, ref, name string) ([]byte, error) {
	n, ct, err := r.st.GetSecret(ctx, ref, name)
	if err != nil {
		return nil, fmt.Errorf("secret %s: %w", name, err)
	}
	return secrets.Open(dek, ref, name, n, ct)
}

func (r *Runner) putSecret(ctx context.Context, dek []byte, ref, name string, plain []byte) error {
	n, ct, err := secrets.Seal(dek, ref, name, plain)
	if err != nil {
		return err
	}
	return r.st.PutSecret(ctx, ref, name, n, ct)
}

func privateKey(der []byte) (*rsa.PrivateKey, error) {
	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, errors.New("stored private key does not parse")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("stored private key is not RSA")
	}
	return rk, nil
}

// keyFromRow is a project_key row as a verification key.
func keyFromRow(row store.KeyRow) (jwtx.Key, error) {
	var j struct{ N, E string }
	if err := json.Unmarshal(row.JWK, &j); err != nil {
		return jwtx.Key{}, err
	}
	return jwtx.KeyFromJWK(row.KID, jwtx.Class(row.Class), j.N, j.E)
}

// keyRow is a verification key as a project_key row (its public JWK).
func keyRow(ref string, k jwtx.Key) (store.KeyRow, error) {
	set, err := jwtx.MarshalJWKS([]jwtx.Key{k})
	if err != nil {
		return store.KeyRow{}, err
	}
	var s struct{ Keys []json.RawMessage }
	if err := json.Unmarshal(set, &s); err != nil {
		return store.KeyRow{}, err
	}
	return store.KeyRow{Ref: ref, KID: k.KID, Class: string(k.Class), JWK: s.Keys[0]}, nil
}

// spec is the project's state as the agent applies it at generation gen with
// configuration cfg: placement from the row, secrets unwrapped, the SCRAM
// salts of the platform's roles, and the keys stored so far.
func (r *Runner) spec(ctx context.Context, p store.Project, epoch, gen int64, cfg store.ProjectConfig) (agent.Spec, error) {
	s, err := bareSpec(p, epoch, gen, cfg)
	if err != nil {
		return s, err
	}
	dek, err := r.dek(ctx, p.Ref, false)
	if err != nil {
		return s, err
	}
	defer clear(dek)
	get := func(name string) (string, error) {
		b, err := r.secret(ctx, dek, p.Ref, name)
		return string(b), err
	}
	sec := bootstrap.Secrets{ScramSalts: map[string][]byte{}}
	for _, v := range []struct {
		dst  *string
		name string
	}{
		{&sec.SupabaseAdminPassword, "pg.supabase_admin.password"},
		{&sec.PostgresPassword, "pg.postgres.password"},
		{&sec.AuthenticatorPassword, "pg.authenticator.password"},
		{&sec.PgsodiumRootKey, "pgsodium.root_key"},
	} {
		if *v.dst, err = get(v.name); err != nil {
			return s, err
		}
	}
	for _, role := range scramRoles {
		if sec.ScramSalts[role], err = pgsock.ScramSalt(dek, p.Ref, role); err != nil {
			return s, err
		}
	}
	s.Secrets = sec
	rows, err := r.st.ListKeys(ctx, p.Ref)
	if err != nil {
		return s, err
	}
	for _, row := range rows {
		k, err := keyFromRow(row)
		if err != nil {
			return s, fmt.Errorf("stored key %s: %w", row.KID, err)
		}
		s.Keys = append(s.Keys, k)
	}
	return s, nil
}

// bareSpec is the spec without secrets or keys: enough to stop, remove and
// purge, which must work after the keys are destroyed.
func bareSpec(p store.Project, epoch, gen int64, cfg store.ProjectConfig) (agent.Spec, error) {
	if p.UID == nil {
		return agent.Spec{}, fmt.Errorf("project %s is not placed", p.Ref)
	}
	s := agent.Spec{Ref: p.Ref, Epoch: epoch, Generation: gen, UID: *p.UID, GID: *p.UID,
		DiskQuotaMB: cfg.DiskQuotaMB, MemMB: cfg.MemMB, Pids: clusterPids, GUC: cfg.GUC, UserRoles: p.UserRoles}
	if p.SubnetIndex != nil {
		s.SubnetIndex = *p.SubnetIndex
	}
	return s, nil
}

// SpecFor is a project's desired state from the store (generation =
// project.generation, the current control-plane epoch), secrets unwrapped.
// Boot and `project check` use it.
func (r *Runner) SpecFor(ctx context.Context, ref string) (agent.Spec, error) {
	p, err := r.st.GetProject(ctx, ref)
	if err != nil {
		return agent.Spec{}, err
	}
	epoch, err := r.st.Epoch(ctx)
	if err != nil {
		return agent.Spec{}, err
	}
	return r.spec(ctx, p, epoch, p.Generation, p.Config)
}

// current is the spec of the operation's project at its desired generation.
func (x *job) current(ctx context.Context) (agent.Spec, error) {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return agent.Spec{}, err
	}
	return x.r.spec(ctx, p, x.op.Epoch, p.Generation, p.Config)
}

// 2: the data key, the passwords, the two platform key pairs, jwt.secret
// and the pgsodium root key.
func (x *job) createSecrets(ctx context.Context) error {
	dek, err := x.r.dek(ctx, x.op.Ref, true)
	if err != nil {
		return err
	}
	defer clear(dek)
	for _, m := range secretMakers {
		_, _, err := x.r.st.GetSecret(ctx, x.op.Ref, m.name)
		if err == nil {
			continue
		}
		if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		plain, err := m.make()
		if err != nil {
			return err
		}
		err = x.r.putSecret(ctx, dek, x.op.Ref, m.name, plain)
		clear(plain)
		if err != nil {
			return err
		}
	}
	return nil
}

// 3: placement (a resumed step gets the stored placement back), the project
// directory and the project network.
func (x *job) place(ctx context.Context) error {
	if _, err := x.r.st.Place(ctx, x.op.Ref); err != nil {
		return err
	}
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	if err := x.r.ag.EnsureDir(ctx, s); err != nil {
		return err
	}
	return x.r.ag.EnsureNetwork(ctx, s)
}

// 4a and 4: the two-phase first boot. EnsureCluster advances one phase per
// call: the call at 4a performs the first boot, the call at 4 the first
// networked start (or adopts it, when a resumed 4a already made it). These
// are the only specs with FirstBoot set — the one permission to initialise,
// and so empty, a data directory — and only while this create still has the
// project provisioning.
func (x *job) clusterFirstBoot(ctx context.Context) error {
	p, err := x.r.st.GetProject(ctx, x.op.Ref)
	if err != nil {
		return err
	}
	s, err := x.r.spec(ctx, p, x.op.Epoch, p.Generation, p.Config)
	if err != nil {
		return err
	}
	s.FirstBoot = x.op.Kind == "create" && p.State == "provisioning"
	return x.r.ag.EnsureCluster(ctx, s)
}

// 6: the two platform keys and every issuer key. An issuer kid equal to a
// platform kid is refused before any key is written.
func (x *job) putKeys(ctx context.Context) error {
	var params struct {
		IssuerJWKS json.RawMessage `json:"issuer_jwks"`
	}
	if err := json.Unmarshal(x.op.Params, &params); err != nil {
		return final("bad_request", errors.New("create parameters do not parse"))
	}
	issuers, err := jwtx.ParseJWKS(params.IssuerJWKS, "issuer")
	if err != nil {
		return final("bad_request", fmt.Errorf("issuer key set: %w", err))
	}
	dek, err := x.r.dek(ctx, x.op.Ref, false)
	if err != nil {
		return err
	}
	defer clear(dek)
	var keys []jwtx.Key
	for _, class := range []jwtx.Class{"anon", "service_role"} {
		der, err := x.r.secret(ctx, dek, x.op.Ref, "jwt."+string(class)+".private")
		if err != nil {
			return err
		}
		priv, err := privateKey(der)
		clear(der)
		if err != nil {
			return err
		}
		keys = append(keys, jwtx.Key{KID: jwtx.KID(&priv.PublicKey), Class: class, Pub: &priv.PublicKey})
	}
	for _, k := range issuers {
		if k.KID == keys[0].KID || k.KID == keys[1].KID {
			return final("bad_request", errors.New("issuer kid collides with a platform kid"))
		}
	}
	for _, k := range append(keys, issuers...) {
		row, err := keyRow(x.op.Ref, k)
		if err != nil {
			return err
		}
		if err := x.r.st.PutKey(ctx, row); err != nil {
			return err
		}
	}
	return nil
}

// 7: the anon and service_role tokens, signed with the stored keys (their
// kid is the stored key's thumbprint), valid for ten years.
func (x *job) mintTokens(ctx context.Context) error {
	dek, err := x.r.dek(ctx, x.op.Ref, false)
	if err != nil {
		return err
	}
	defer clear(dek)
	for _, class := range []string{"anon", "service_role"} {
		name := "token." + class
		if _, _, err := x.r.st.GetSecret(ctx, x.op.Ref, name); err == nil {
			continue
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
		der, err := x.r.secret(ctx, dek, x.op.Ref, "jwt."+class+".private")
		if err != nil {
			return err
		}
		priv, err := privateKey(der)
		clear(der)
		if err != nil {
			return err
		}
		iat := time.Now()
		tok, err := jwtx.Sign(priv, jwtx.KID(&priv.PublicKey), map[string]any{"role": class, "iss": "supapace",
			"ref": x.op.Ref, "iat": iat.Unix(), "exp": iat.AddDate(10, 0, 0).Unix()})
		if err != nil {
			return err
		}
		if err := x.r.putSecret(ctx, dek, x.op.Ref, name, []byte(tok)); err != nil {
			return err
		}
	}
	return nil
}

// 9: PostgREST (its files rendered and its start gate passed by the agent).
func (x *job) postgrest(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	return x.r.ag.EnsurePostgREST(ctx, s)
}

// 11: the active route, the gateway at that route file, and the end-to-end
// probe with the anon token (PostgREST's readiness check).
func (x *job) publish(ctx context.Context) error {
	s, err := x.current(ctx)
	if err != nil {
		return err
	}
	return x.expose(ctx, s)
}

func (x *job) expose(ctx context.Context, s agent.Spec) error {
	rt := x.r.ag.RouteFor(s, "active")
	gen, err := x.r.ag.SetRoute(ctx, x.op.Ref, &rt)
	if err != nil {
		return err
	}
	if err := x.r.waitGateway(ctx, gen); err != nil {
		return err
	}
	dek, err := x.r.dek(ctx, x.op.Ref, false)
	if err != nil {
		return err
	}
	tok, err := x.r.secret(ctx, dek, x.op.Ref, "token.anon")
	clear(dek)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(x.r.probeWindow)
	for {
		err := x.r.ag.ProbeREST(ctx, x.op.Ref, string(tok))
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			x.drainRoute(ctx, s)
			return err
		}
		if err := sleep(ctx, x.r.probeEvery); err != nil {
			x.drainRoute(ctx, s)
			return err
		}
	}
}

// drainRoute sets the route back to draining after a failed probe: a route
// is never left active for a project that is not. The step's context may
// have expired, so it has its own short bound.
func (x *job) drainRoute(ctx context.Context, s agent.Spec) {
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	rt := x.r.ag.RouteFor(s, "draining")
	if _, err := x.r.ag.SetRoute(dctx, x.op.Ref, &rt); err != nil {
		x.r.log.Error("draining the route after a failed probe", "op", x.op.ID, "ref", x.op.Ref, "err", x.r.text(err))
	}
}

// waitGateway waits, within ctx, until the gateway serves route file
// generation gen or later.
func (r *Runner) waitGateway(ctx context.Context, gen int64) error {
	for {
		got, err := r.ag.GatewayGeneration(ctx)
		if err == nil && got >= gen {
			return nil
		}
		if ctx.Err() != nil {
			if err == nil {
				err = fmt.Errorf("gateway at route generation %d, want %d: %w", got, gen, ctx.Err())
			}
			return err
		}
		if err := sleep(ctx, r.probeEvery); err != nil {
			return err
		}
	}
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// 12: active, only now that the probe has passed end to end, and the
// operation done, in one transaction that an abort which won refuses.
func (x *job) activate(ctx context.Context) error {
	beforeFinishCreate()
	if err := x.record(ctx); err != nil {
		return err
	}
	// Under the step's deadline: the write is one transaction, so a cut
	// either left it committed or the step repeats.
	if err := x.r.st.FinishCreate(ctx, x.op.ID); err != nil {
		return err
	}
	return errFinished
}

// strictJSON decodes exactly one JSON value with no unknown members.
func strictJSON(b []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return err
	}
	if d.More() {
		return errors.New("trailing data")
	}
	return nil
}

// beforeFinishCreate runs just before step 12 checks its lock and writes;
// a test seam (no-op otherwise), used to land
// an abort in that window.
var beforeFinishCreate = func() {}
