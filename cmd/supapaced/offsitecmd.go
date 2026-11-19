package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/Amphoze/supapace/internal/offsite"
	"github.com/Amphoze/supapace/internal/s3x"
	"github.com/Amphoze/supapace/internal/secrets"
)

// offsiteCommands maps a sub-command of `offsite` to its entry point; each
// file adds its own from an init function, as commands does.
var offsiteCommands = map[string]func(args []string) int{}

// loadKEK reads the node key; tests substitute their own.
var loadKEK = secrets.LoadKEK

func init() {
	commands["offsite"] = offsiteCmd
	offsiteCommands["set"] = offsiteSet
	offsiteCommands["show"] = offsiteShow
}

func offsiteCmd(args []string) int {
	if len(args) > 0 {
		if cmd, ok := offsiteCommands[args[0]]; ok {
			return cmd(args[1:])
		}
	}
	names := make([]string, 0, len(offsiteCommands))
	for k := range offsiteCommands {
		names = append(names, k)
	}
	slices.Sort(names)
	fmt.Fprintf(stderr, "usage: supapaced offsite %s ...\n", strings.Join(names, "|"))
	return 2
}

// offsiteSet saves the object-store declaration. Credentials come from files
// only (access key, newline, secret key), never from the command line; the
// command is offline.
func offsiteSet(args []string) int {
	fl := flag.NewFlagSet("offsite set", flag.ContinueOnError)
	fl.SetOutput(stderr)
	var d offsite.Declaration
	var virtualHost bool
	var caFile string
	keyNames := []string{"projects-write-keys", "projects-read-keys", "cp-write-keys", "cp-read-keys"}
	keyFiles := map[string]*string{}
	fl.StringVar(&d.Endpoint, "endpoint", "", "https://host[:port] (required)")
	fl.StringVar(&d.Region, "region", "", "the store's region (required)")
	fl.BoolVar(&virtualHost, "virtual-host", false, "address buckets as bucket.host (default: path style)")
	fl.StringVar(&caFile, "ca-file", "", "CA bundle (PEM) for the endpoint, in place of the system's roots")
	fl.StringVar(&d.Projects.Name, "projects-bucket", "", "bucket of the projects' copies (required)")
	fl.StringVar(&d.Projects.Prefix, "projects-prefix", "", "prefix of every key in the projects bucket")
	fl.StringVar(&d.ControlPlane.Name, "cp-bucket", "", "bucket of the control plane's copy (required)")
	fl.StringVar(&d.ControlPlane.Prefix, "cp-prefix", "", "prefix of every key in the control-plane bucket")
	for _, name := range keyNames {
		keyFiles[name] = fl.String(name, "", "file: access key, newline, secret key (required)")
	}
	if err := fl.Parse(args); err != nil {
		return 2
	}
	usage := ""
	switch {
	case fl.NArg() != 0:
		usage = "unexpected argument " + fl.Arg(0)
	case d.Endpoint == "" || d.Region == "" || d.Projects.Name == "" || d.ControlPlane.Name == "":
		usage = "--endpoint, --region, --projects-bucket and --cp-bucket are required"
	}
	for _, name := range keyNames {
		if *keyFiles[name] == "" && usage == "" {
			usage = "--" + name + " is required"
		}
	}
	if usage != "" {
		fmt.Fprintf(stderr, "supapaced offsite set: %s\n", usage)
		fl.Usage()
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced offsite set: must run as root")
		return 1
	}
	if err := setDeclaration(d, !virtualHost, caFile, keyFiles); err != nil {
		fmt.Fprintf(stderr, "supapaced offsite set: %s\n", strings.Join(strings.Fields(err.Error()), " "))
		return 1
	}
	fmt.Fprintf(stdout, "supapaced offsite set: wrote %s\n", paths.OffsiteSealed())
	return 0
}

func setDeclaration(d offsite.Declaration, pathStyle bool, caFile string, keyFiles map[string]*string) error {
	d.PathStyle = pathStyle
	if caFile != "" {
		b, err := os.ReadFile(caFile)
		if err != nil {
			return err
		}
		d.CAPEM = string(b)
	}
	var err error
	for name, c := range map[string]*offsite.Credential{
		"projects-write-keys": &d.Projects.Write, "projects-read-keys": &d.Projects.Read,
		"cp-write-keys": &d.ControlPlane.Write, "cp-read-keys": &d.ControlPlane.Read,
	} {
		if *c, err = readKeys(*keyFiles[name]); err != nil {
			return fmt.Errorf("--%s: %w", name, err)
		}
	}
	// The client's own checks: endpoint, bucket names, region, credentials, CA.
	for _, b := range []offsite.Bucket{d.Projects, d.ControlPlane} {
		for _, c := range []offsite.Credential{b.Write, b.Read} {
			if _, err := s3x.New(s3x.Config{Endpoint: d.Endpoint, Region: d.Region, Bucket: b.Name, PathStyle: d.PathStyle,
				AccessKey: c.AccessKey, SecretKey: c.SecretKey, CAPEM: d.CAPEM, Timeout: time.Minute}); err != nil {
				return err
			}
		}
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return err
	}
	defer clear(k[:])
	return offsite.Save(paths, k, d)
}

// readKeys reads a keys file: the access key, a newline, the secret key and
// an optional final newline; nothing else. Errors never quote the file.
func readKeys(path string) (offsite.Credential, error) {
	f, err := os.Open(path)
	if err != nil {
		return offsite.Credential{}, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 4097))
	if err != nil {
		return offsite.Credential{}, err
	}
	defer clear(b)
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	bad := len(b) > 4096 || len(lines) != 2
	for _, l := range lines {
		bad = bad || l == ""
		for i := 0; i < len(l); i++ {
			bad = bad || l[i] <= ' ' || l[i] == 0x7f
		}
	}
	if bad {
		return offsite.Credential{}, errors.New("a keys file holds exactly two lines, the access key and the secret key, without spaces")
	}
	return offsite.Credential{AccessKey: lines[0], SecretKey: lines[1]}, nil
}

// showBucket and showDoc are what `offsite show` prints: no credential, only
// whether each is present.
type showBucket struct {
	Name     string `json:"name"`
	Prefix   string `json:"prefix"`
	WriteSet bool   `json:"write_credential"`
	ReadSet  bool   `json:"read_credential"`
}

type showDoc struct {
	State        offsite.State `json:"state"`
	Endpoint     string        `json:"endpoint,omitempty"`
	Region       string        `json:"region,omitempty"`
	PathStyle    bool          `json:"path_style,omitempty"`
	CASet        bool          `json:"ca,omitempty"`
	Projects     *showBucket   `json:"projects,omitempty"`
	ControlPlane *showBucket   `json:"control_plane,omitempty"`
}

func showDocument(d offsite.Declaration, st offsite.State) showDoc {
	if st == offsite.StateUndeclared {
		return showDoc{State: st}
	}
	b := func(b offsite.Bucket) *showBucket {
		return &showBucket{b.Name, b.Prefix, b.Write.AccessKey != "" && b.Write.SecretKey != "", b.Read.AccessKey != "" && b.Read.SecretKey != ""}
	}
	return showDoc{st, d.Endpoint, d.Region, d.PathStyle, d.CAPEM != "", b(d.Projects), b(d.ControlPlane)}
}

// offsiteShow prints the declaration without secrets, with its state; an
// undeclared node is not an error.
func offsiteShow(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: supapaced offsite show")
		return 2
	}
	if rootOnly && os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "supapaced offsite show: must run as root")
		return 1
	}
	doc, err := loadShow()
	if err != nil {
		fmt.Fprintf(stderr, "supapaced offsite show: %s\n", strings.Join(strings.Fields(err.Error()), " "))
		return 1
	}
	b, _ := json.MarshalIndent(doc, "", "  ")
	fmt.Fprintf(stdout, "%s\n", bytes.TrimSpace(b))
	return 0
}

func loadShow() (showDoc, error) {
	// No file needs no key.
	if _, err := os.Lstat(paths.OffsiteSealed()); errors.Is(err, fs.ErrNotExist) {
		return showDocument(offsite.Declaration{}, offsite.StateUndeclared), nil
	}
	k, err := loadKEK(paths.KEK())
	if err != nil {
		return showDoc{}, err
	}
	defer clear(k[:])
	d, st, err := offsite.Load(paths, k)
	if err != nil {
		return showDoc{}, err
	}
	return showDocument(d, st), nil
}
