// Package btm parses the output of `sfltool dumpbtm` (Background Task Management, macOS 13+),
// which lists login items, launch agents/daemons and apps registered to run in the background.
package btm

import (
	"regexp"
	"strings"
)

// Item is one registered background item.
type Item struct {
	Name           string
	DeveloperName  string
	Type           string // e.g. "legacy daemon", "login item", "app", "developer"
	Disposition    string // e.g. "enabled, allowed, not notified"
	Identifier     string
	URL            string
	ExecutablePath string
}

// Enabled reports whether the item is currently enabled.
func (i Item) Enabled() bool {
	d := strings.ToLower(i.Disposition)
	return strings.Contains(d, "enabled") && !strings.Contains(d, "disabled")
}

// Grouping reports whether the record only represents a developer, not a runnable item.
func (i Item) Grouping() bool { return i.Type == "developer" }

// DisplayName returns the item name, falling back to its identifier when unnamed.
func (i Item) DisplayName() string {
	if i.Name != "" && i.Name != "(null)" {
		return i.Name
	}
	return i.Identifier
}

// Where returns the most useful location string for the item.
func (i Item) Where() string {
	switch {
	case i.ExecutablePath != "":
		return i.ExecutablePath
	case i.URL != "" && i.URL != "(null)":
		return i.URL
	}
	return i.Identifier
}

var (
	itemStart = regexp.MustCompile(`^\s*#\d+:\s*$`)
	field     = regexp.MustCompile(`^\s+([A-Za-z][A-Za-z ]*?): (.*)$`)
	typeRe    = regexp.MustCompile(`^(.*?)\s*\(0x[0-9a-fA-F]+\)\s*$`)
)

// Parse reads dumpbtm output. Records are introduced by "#N:" at the top level; the nested
// "Embedded Item Identifiers" entries (also "#N:" but more deeply indented) are ignored.
func Parse(out string) []Item {
	var items []Item
	var cur *Item
	flush := func() {
		if cur != nil {
			items = append(items, *cur)
			cur = nil
		}
	}
	inEmbedded := false
	for _, line := range strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n") {
		if itemStart.MatchString(line) && indent(line) <= 1 {
			flush()
			cur = &Item{}
			inEmbedded = false
			continue
		}
		if cur == nil {
			continue
		}
		if strings.Contains(line, "Embedded Item Identifiers") {
			inEmbedded = true
			continue
		}
		m := field.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		key, val := m[1], strings.TrimSpace(m[2])
		if inEmbedded && key != "Parent Identifier" {
			continue
		}
		switch key {
		case "Name":
			cur.Name = val
		case "Developer Name":
			cur.DeveloperName = val
		case "Type":
			if t := typeRe.FindStringSubmatch(val); t != nil {
				val = t[1]
			}
			cur.Type = val
		case "Disposition":
			cur.Disposition = strings.Trim(val[:indexOr(val, "(0x")], "[] ")
		case "Identifier":
			cur.Identifier = val
		case "URL":
			cur.URL = val
		case "Executable Path":
			cur.ExecutablePath = val
		}
	}
	flush()
	return items
}

func indent(s string) int { return len(s) - len(strings.TrimLeft(s, " ")) }

func indexOr(s, sub string) int {
	if i := strings.Index(s, sub); i >= 0 {
		return i
	}
	return len(s)
}
