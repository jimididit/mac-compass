# Contributing

## Build and test

```bash
go build ./...
go vet ./...
go test ./...                  # runs anywhere; macOS-only tests are build-tagged
GOOS=darwin go vet ./...       # catches macOS-only compile errors from any OS
```

CI additionally runs the tests and a full `run-all` on real macOS 15 and 26 (Apple Silicon and Intel).
Keep new work compiling and passing on all of them.

## Principles

- **Read-only.** A check must never change system state. Tests reject known mutating tools.
- **Absolute paths, no shell unless needed.** Use `command` + `args`; use `script` only for pipes.
- **No guessing output formats.** If you cannot run a command on a Mac, add the check, let CI capture the
  real output (the `macos-run-*` artifacts), then write the evaluator against that output.
- **A clean machine must look clean.** Treat "nothing found" exit codes as success with `ok_exit`.

## Adding a check

1. Add an entry to `internal/catalog/checks.yaml` with a unique, stable `id` (`section.slug`), a `section`,
   a `name`, and either `command`+`args` or `script`. Set `sudo`, `ok_exit`, `macos_min`/`macos_max`,
   `arch`, `optional`, and `attack` (MITRE ATT&CK ids) where they apply. The catalog is validated strictly
   when loaded, so typos fail the tests.
2. To turn output into a judgement, add an evaluator in `internal/findings` and register it under the
   check `id`. Evaluators are pure functions of the captured output.
3. To track the check in baselines, add an extractor in `internal/baseline/extract*.go` (and a `meta`
   entry with a label and severity). Strip anything that changes per run (pids, timestamps, sizes).
4. Test against real output: copy the relevant `stdout` from a CI artifact into
   `internal/findings/testdata/<macos>-<arch>/<id>.stdout` and assert on it, plus synthetic good and bad
   cases. Scrub anything personal from fixtures.

## Pull requests

Branch from `main`, keep PRs focused, and make sure CI is green. Commit messages describe the change and
why; no tool or author attribution trailers.
