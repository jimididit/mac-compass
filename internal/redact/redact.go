// Package redact masks the host name and the invoking user's name so a report or snapshot
// can be shared without identifying the machine or its owner. It is deliberately narrow:
// it does not hide serial numbers, UUIDs, IP addresses or the names of other accounts.
package redact

import (
	"bytes"
	"io"
	"os"
	"os/user"
	"regexp"
	"strings"

	"github.com/jimididit/mac-compass/internal/baseline"
	"github.com/jimididit/mac-compass/internal/output"
)

const (
	hostMask = "[host]"
	userMask = "[user]"
)

// Redactor replaces identifying strings. The zero value redacts nothing.
type Redactor struct {
	host *strings.Replacer
	user *regexp.Regexp
}

// New builds a Redactor for the given host and user names. Names too short or too generic
// to mask safely (they would mangle unrelated text) are ignored.
func New(hostname, username string) Redactor {
	var r Redactor
	if hostname = strings.TrimSpace(hostname); len(hostname) >= 3 {
		pairs := []string{hostname, hostMask}
		if short, _, ok := strings.Cut(hostname, "."); ok && len(short) >= 3 {
			pairs = append(pairs, short, hostMask)
		}
		r.host = strings.NewReplacer(pairs...)
	}
	switch strings.ToLower(username) {
	case "", "root", "admin", "user", "runner":
		// "runner" is kept: it is the GitHub Actions account, not a person.
	default:
		if len(username) >= 3 {
			r.user = regexp.MustCompile(`\b` + regexp.QuoteMeta(username) + `\b`)
		}
	}
	return r
}

// ForCurrentUser builds a Redactor for this machine and the user who invoked the tool
// (the sudo caller when run under sudo).
func ForCurrentUser() Redactor {
	host, _ := os.Hostname()
	name := os.Getenv("SUDO_USER")
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	return New(host, name)
}

// String redacts s.
func (r Redactor) String(s string) string {
	if r.host != nil {
		s = r.host.Replace(s)
	}
	if r.user != nil {
		s = r.user.ReplaceAllString(s, userMask)
	}
	return s
}

func (r Redactor) strings(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.String(s)
	}
	return out
}

// Report redacts every string in a report in place.
func (r Redactor) Report(rep *output.Report) {
	rep.Host.Hostname = r.String(rep.Host.Hostname)
	for i := range rep.Sections {
		for j := range rep.Sections[i].Checks {
			c := &rep.Sections[i].Checks[j]
			c.Stdout, c.Stderr, c.Error = r.String(c.Stdout), r.String(c.Stderr), r.String(c.Error)
		}
	}
	for i := range rep.Findings {
		f := &rep.Findings[i]
		f.Title, f.Detail, f.Remediation = r.String(f.Title), r.String(f.Detail), r.String(f.Remediation)
	}
	for i := range rep.Suppressed {
		f := &rep.Suppressed[i]
		f.Title, f.Detail, f.Remediation, f.Reason = r.String(f.Title), r.String(f.Detail), r.String(f.Remediation), r.String(f.Reason)
	}
}

// Snapshot redacts a snapshot in place. Redact both sides of a comparison or neither.
func (r Redactor) Snapshot(s *baseline.Snapshot) {
	s.Redacted = true
	s.Host.Hostname = r.String(s.Host.Hostname)
	for id, e := range s.Checks {
		e.Items = r.strings(e.Items)
		s.Checks[id] = e
	}
}

// lineWriter redacts complete lines so a name split across two writes is still caught.
type lineWriter struct {
	r   Redactor
	w   io.Writer
	buf bytes.Buffer
}

// Writer wraps w so everything written through it is redacted. Call Flush when done.
func (r Redactor) Writer(w io.Writer) *LineWriter { return &LineWriter{lineWriter{r: r, w: w}} }

// LineWriter is an io.Writer that redacts line by line.
type LineWriter struct{ lineWriter }

// Write buffers p and forwards every complete line, redacted.
func (l *LineWriter) Write(p []byte) (int, error) {
	l.buf.Write(p)
	for {
		i := bytes.IndexByte(l.buf.Bytes(), '\n')
		if i < 0 {
			return len(p), nil
		}
		line := string(l.buf.Next(i + 1))
		if _, err := io.WriteString(l.w, l.r.String(line)); err != nil {
			return 0, err
		}
	}
}

// Flush writes any trailing partial line.
func (l *LineWriter) Flush() error {
	if l.buf.Len() == 0 {
		return nil
	}
	_, err := io.WriteString(l.w, l.r.String(l.buf.String()))
	l.buf.Reset()
	return err
}
