// Package render turns a report into shareable formats: a self-contained HTML page and SARIF.
package render

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"github.com/jimididit/mac-compass/internal/output"
)

// HTML renders the report as one self-contained page: no scripts, no external requests, and a
// content-security policy that forbids both, so a report containing hostile text from the examined
// machine cannot do anything when opened. All values are escaped by html/template.
func HTML(rep output.Report) ([]byte, error) {
	var buf bytes.Buffer
	if err := page.Execute(&buf, newView(rep)); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

type findingView struct {
	output.Finding
	Class  string
	Label  string
	Reason string // set for suppressed findings
}

type group struct {
	Title    string
	Class    string
	Findings []findingView
}

type view struct {
	Rep        output.Report
	Groups     []group
	Suppressed []findingView
	Checks     []output.CheckResult
	Counts     []count
	Started    string
}

type count struct {
	Label string
	N     int
	Class string
}

var order = []struct {
	sev   output.Severity
	title string
}{
	{output.SeverityCritical, "Critical"}, {output.SeverityHigh, "High"}, {output.SeverityMedium, "Medium"},
	{output.SeverityLow, "Low"}, {output.SeverityInfo, "Info (failed)"},
}

func newView(rep output.Report) view {
	v := view{Rep: rep, Started: rep.StartedAt.UTC().Format("2006-01-02 15:04 UTC")}
	bySev := map[output.Severity][]findingView{}
	var errs, infos []findingView
	for _, f := range rep.Findings {
		fv := findingView{Finding: f, Class: string(f.Severity), Label: string(f.Severity)}
		switch f.Status {
		case output.StatusFail:
			bySev[f.Severity] = append(bySev[f.Severity], fv)
		case output.StatusError:
			fv.Class, fv.Label = "error", "error"
			errs = append(errs, fv)
		case output.StatusInfo:
			fv.Class, fv.Label = "info", "info"
			infos = append(infos, fv)
		}
	}
	for _, o := range order {
		if fs := bySev[o.sev]; len(fs) > 0 {
			v.Groups = append(v.Groups, group{Title: o.title, Class: string(o.sev), Findings: fs})
		}
	}
	if len(errs) > 0 {
		v.Groups = append(v.Groups, group{Title: "Checks that could not run", Class: "error", Findings: errs})
	}
	if len(infos) > 0 {
		v.Groups = append(v.Groups, group{Title: "For your information", Class: "info", Findings: infos})
	}
	for _, s := range rep.Suppressed {
		v.Suppressed = append(v.Suppressed, findingView{Finding: s.Finding, Class: "accepted", Label: "accepted", Reason: s.Reason})
	}
	for _, sec := range rep.Sections {
		v.Checks = append(v.Checks, sec.Checks...)
	}
	s := rep.Summary
	v.Counts = []count{
		{"high or critical", s.FailBySeverity[output.SeverityHigh] + s.FailBySeverity[output.SeverityCritical], "high"},
		{"medium", s.FailBySeverity[output.SeverityMedium], "medium"},
		{"low", s.FailBySeverity[output.SeverityLow], "low"},
		{"info", s.Info, "info"},
		{"passed", s.Pass, "pass"},
		{"errors", s.Error, "error"},
	}
	return v
}

var funcs = template.FuncMap{
	"lines": func(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") },
	"attack": func(id string) string {
		return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/"
	},
	"ms": func(n int64) string { return fmt.Sprintf("%.1fs", float64(n)/1000) },
	"status": func(c output.CheckResult) string {
		switch {
		case c.Skipped:
			return "skipped"
		case c.Ok:
			return "ok"
		}
		return "failed"
	},
}

var page = template.Must(template.New("report").Funcs(funcs).Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>mac-compass report</title>
<style>
:root{--bg:#fff;--fg:#1f2328;--muted:#59636e;--card:#f6f8fa;--line:#d1d9e0;--high:#cf222e;--medium:#bc4c00;--low:#9a6700;--info:#0969da;--pass:#1a7f37;--error:#8250df;--accepted:#59636e}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--card:#151b23;--line:#3d444d;--high:#ff7b72;--medium:#ffa657;--low:#e3b341;--info:#79c0ff;--pass:#56d364;--error:#d2a8ff;--accepted:#9198a1}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:920px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:1.6rem;margin:0 0 4px}
h2{font-size:1.15rem;margin:32px 0 12px;padding-bottom:6px;border-bottom:1px solid var(--line)}
.meta{color:var(--muted);margin:0 0 20px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
.card b{display:block;font-size:1.6rem;line-height:1.1}
.card span{color:var(--muted);font-size:.85rem}
.card.high b{color:var(--high)}.card.medium b{color:var(--medium)}.card.low b{color:var(--low)}.card.info b{color:var(--info)}.card.pass b{color:var(--pass)}.card.error b{color:var(--error)}
.finding{background:var(--card);border:1px solid var(--line);border-left:4px solid var(--line);border-radius:6px;padding:10px 14px;margin:10px 0}
.finding.critical,.finding.high{border-left-color:var(--high)}.finding.medium{border-left-color:var(--medium)}.finding.low{border-left-color:var(--low)}.finding.info{border-left-color:var(--info)}.finding.error{border-left-color:var(--error)}.finding.accepted{border-left-color:var(--accepted)}
.tag{display:inline-block;font-size:.72rem;font-weight:600;text-transform:uppercase;letter-spacing:.04em;border:1px solid currentColor;border-radius:4px;padding:0 6px;margin-right:8px;vertical-align:1px}
.tag.critical,.tag.high{color:var(--high)}.tag.medium{color:var(--medium)}.tag.low{color:var(--low)}.tag.info{color:var(--info)}.tag.error{color:var(--error)}.tag.accepted{color:var(--accepted)}
.finding h3{font-size:1rem;margin:0}
pre{margin:8px 0 0;padding:8px 10px;background:var(--bg);border:1px solid var(--line);border-radius:6px;overflow-x:auto;font:12.5px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;word-break:break-word}
.fix{margin:8px 0 0}.fix b{color:var(--pass)}
.small{color:var(--muted);font-size:.82rem;margin-top:6px}
a{color:var(--info)}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th,td{text-align:left;padding:5px 8px;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600}
td.failed{color:var(--high)}td.skipped{color:var(--muted)}td.ok{color:var(--pass)}
details{margin:8px 0}summary{cursor:pointer;color:var(--muted)}
footer{margin-top:40px;color:var(--muted);font-size:.8rem}
@media print{body{background:#fff;color:#000}.finding{break-inside:avoid}}
</style>
</head>
<body>
<main>
<h1>mac-compass report</h1>
<p class="meta">{{with .Rep.Host.Hostname}}{{.}} &middot; {{end}}macOS {{.Rep.Host.MacOSVersion}}{{with .Rep.Host.MacOSBuild}} ({{.}}){{end}} &middot; {{.Rep.Host.Arch}} &middot; {{.Started}}
 &middot; mac-compass {{.Rep.Tool.Version}}{{if not .Rep.SudoEnabled}} &middot; run without sudo{{end}}{{if .Rep.VMMode}} &middot; VM mode{{end}}</p>

<div class="cards">
{{range .Counts}}<div class="card {{.Class}}"><b>{{.N}}</b><span>{{.Label}}</span></div>
{{end}}</div>

<h2>Findings</h2>
{{if not .Groups}}<p>No findings.</p>{{end}}
{{range .Groups}}<h3 style="margin:20px 0 4px">{{.Title}}</h3>
{{range .Findings}}<div class="finding {{.Class}}">
<h3><span class="tag {{.Class}}">{{.Label}}</span>{{.Title}}</h3>
{{if .Detail}}<pre>{{.Detail}}</pre>{{end}}
{{if .Remediation}}<p class="fix"><b>Fix:</b> {{.Remediation}}</p>{{end}}
<p class="small">check <code>{{.CheckID}}</code>{{range .Attack}} &middot; <a href="{{attack .}}" rel="noreferrer noopener">{{.}}</a>{{end}}</p>
</div>
{{end}}{{end}}

{{if .Suppressed}}<h2>Accepted by your suppressions file</h2>
{{range .Suppressed}}<div class="finding accepted">
<h3><span class="tag accepted">accepted</span>{{.Title}}</h3>
<p class="small">Reason: {{.Reason}}</p>
</div>
{{end}}{{end}}

<h2>Checks</h2>
<details><summary>{{.Rep.Summary.ChecksOK}} ok, {{.Rep.Summary.ChecksSkipped}} skipped, {{.Rep.Summary.ChecksFailed}} failed</summary>
<table>
<tr><th>Check</th><th>Id</th><th>Result</th><th>Time</th></tr>
{{range .Checks}}<tr><td>{{.Name}}</td><td><code>{{.ID}}</code></td><td class="{{status .}}">{{status .}}{{if .SkipReason}} ({{.SkipReason}}){{end}}</td><td>{{ms .DurationMS}}</td></tr>
{{end}}</table>
</details>

<footer>Generated by mac-compass. Findings are heuristics: a clean result is evidence, not proof, and many findings are normal on a machine you set up yourself.</footer>
</main>
</body>
</html>
`))
