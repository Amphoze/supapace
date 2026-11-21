package bkjob

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/Amphoze/supapace/internal/bklimit"
	"github.com/Amphoze/supapace/internal/walname"
)

var (
	// manifestMax bounds the manifest read, in bytes; a set file of the
	// repository is never larger. Tests lower it.
	manifestMax int64 = bklimit.SetFileMax
	// manifestLineMax bounds one line of it.
	manifestLineMax = 1 << 20
)

// errStop ends the manifest's reading early: its verdict is in.
var errStop = errors.New("stop")

// checkManifest reads the manifest of set from the repository with the tool's
// repo-get — the path relative to the repository as its only argument, the
// job's own environment, never --raw — and refuses, before anything is
// written to the data directory, a set the restore must not write: code
// tablespace for any tablespace or link entry, set_invalid for a manifest the
// tool cannot give (a wrong passphrase, a missing set, a signal), that is
// malformed, too large, or that names a path outside the data directory's
// form. Nothing of the manifest is kept or passed on: it holds the set's own
// key.
func checkManifest(ctx context.Context, stanza, set string) (setKey string, err error) {
	key, err := checkManifestFile(ctx, stanza, set, "backup.manifest")
	if err != nil {
		return key, err
	}
	// The tool falls back to the copy when the main file fails its checksum:
	// the copy, when there is one, passes the same rules.
	rel := "backup/" + stanza + "/" + set + "/backup.manifest.copy"
	if _, serr := os.Lstat(filepath.Join(repoRoot, rel)); serr != nil {
		return key, nil
	}
	key2, err := checkManifestFile(ctx, stanza, set, "backup.manifest.copy")
	if err == nil && key2 != key {
		err = failQuiet(restoreSetInvalid, "the two manifests of set %s hold different keys", set)
	}
	return key, hide(hide(err, key), key2)
}

// checkManifestFile checks one of the set's two manifest files.
func checkManifestFile(ctx context.Context, stanza, set, file string) (setKey string, err error) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(ctx, Tool, "repo-get", "backup/"+stanza+"/"+set+"/"+file)
	errOut := tail{max: outputMax}
	cmd.Stderr = &errOut
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", err
	}
	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("bkjob: running %s: %w", Tool, err)
	}
	m := manifest{stanza: stanza, set: set}
	lr := &io.LimitedReader{R: stdout, N: manifestMax + 1}
	verdict := m.read(lr)
	if verdict == nil && lr.N <= 0 {
		verdict = fmt.Errorf("above %d bytes", manifestMax)
	}
	if verdict != nil {
		cancel() // the rest is not read: the tool is stopped
	}
	werr := cmd.Wait()
	var ee *exec.ExitError
	switch {
	case verdict != nil && errors.Is(verdict, errStop):
		err = m.refusal
	case verdict != nil:
		err = failQuiet(restoreSetInvalid, "the manifest of set %s: %v", set, verdict)
	case werr != nil && errors.As(werr, &ee) && ee.Exited():
		err = failQuiet(restoreSetInvalid, "repo-get of set %s: exit %d: %s", set, ee.ExitCode(), m.toolLine(string(errOut.b)))
	case werr != nil:
		err = failQuiet(restoreSetInvalid, "repo-get of set %s: %v", set, werr)
	case !m.target:
		err = failQuiet(restoreSetInvalid, "the manifest of set %s has no data directory entry", set)
	}
	return m.key, hide(err, m.key)
}

// manifest is the reading of one manifest.
type manifest struct {
	stanza, set string
	section     string
	target      bool   // [backup:target] holds the data directory
	errLine     string // the tool's last error line seen on its standard output
	refusal     error  // the verdict, with errStop
	key         string // the set's own key ([cipher] cipher-pass), kept only to keep it out of messages
}

// read reads the manifest's lines; nil when the whole of it is acceptable.
func (m *manifest) read(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, manifestLineMax)
		if line != nil {
			if verr := m.line(line); verr != nil {
				return verr
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

// readLine is the next line without its newline, at most max bytes.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var b []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if len(b)+len(chunk) > max+1 {
			return nil, fmt.Errorf("a line above %d bytes", max)
		}
		b = append(b, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(b) == 0 {
			return nil, io.EOF
		}
		return bytes.TrimSuffix(b, []byte("\n")), err
	}
}

// line takes one line of the manifest.
func (m *manifest) line(l []byte) error {
	s := string(l)
	switch {
	case s == "":
		return nil
	case strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]"):
		m.section = s[1 : len(s)-1]
		return nil
	case m.section == "":
		// The tool's console, before the manifest's first section.
		if strings.Contains(s, "ERROR: [") {
			m.errLine = s
		}
		return nil
	}
	key, val, ok := strings.Cut(s, "=")
	if !ok {
		return fmt.Errorf("a line of section %s is not key=value", quoteName(m.section))
	}
	switch m.section {
	case "cipher":
		if key == "cipher-pass" {
			m.key = strings.Trim(val, `"`)
		}
	case "backup:target":
		if strings.HasPrefix(key, "pg_tblspc") {
			return m.refuse(restoreTablespace, "a tablespace entry %s", key)
		}
		// Member names exact, as the tool reads them (the standard decoder
		// would match "Type"); one "type" only.
		var v map[string]any
		if err := json.Unmarshal([]byte(val), &v); err != nil || strings.Count(val, `"type"`) != 1 {
			return fmt.Errorf("the value of %s in [backup:target] is not an object with one type", quoteName(key))
		}
		typ, _ := v["type"].(string)
		switch {
		case typ == "link":
			return m.refuse(restoreTablespace, "a link entry %s", key)
		case key != "pg_data" || typ != "path":
			return fmt.Errorf("an entry %s of type %s in [backup:target]", quoteName(key), quoteName(typ))
		}
		m.target = true
	case "target:link":
		return m.refuse(restoreTablespace, "a link entry %s", key)
	case "target:file", "target:path":
		if strings.HasPrefix(key, "pg_tblspc") || strings.HasPrefix(key, "pg_data/pg_tblspc/") {
			return m.refuse(restoreTablespace, "a tablespace entry %s", key)
		}
		if !(key == "pg_data" && m.section == "target:path") && !m.dataPath(key) {
			return fmt.Errorf("an entry %s outside the data directory's form in [%s]", quoteName(key), m.section)
		}
		if !json.Valid([]byte(val)) || !strings.HasPrefix(val, "{") {
			return fmt.Errorf("the value of %s is not an object", quoteName(key))
		}
	}
	return nil
}

// dataPath: key is pg_data/<path> with a path the repository's own names
// allow (walname: 1 to 512 bytes of a fixed set, no empty, "." or ".." part).
func (m *manifest) dataPath(key string) bool {
	k, _, _, ok := walname.RepoPath(m.stanza, "backup/"+m.stanza+"/"+m.set+"/"+key)
	return ok && k == walname.SetFile
}

// refuse records the verdict code and stops the reading.
func (m *manifest) refuse(code, format string, key string) error {
	m.refusal = failQuiet(code, format+" in the manifest of set %s", quoteName(key), m.set)
	return errStop
}

// toolLine is the tool's error line: from its standard output (the console)
// when one was seen there, else from its standard error.
func (m *manifest) toolLine(stderr string) string {
	if m.errLine != "" {
		return strings.TrimSpace(m.errLine)
	}
	if strings.TrimSpace(stderr) == "" {
		return "no output"
	}
	return errorLine(stderr)
}

// quoteName quotes a name read from the manifest, cut to 64 bytes.
func quoteName(s string) string {
	return strconv.QuoteToASCII(s[:min(len(s), 64)])
}
