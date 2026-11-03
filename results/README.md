# Grading output

One directory per build, copied from the grading host.

- `results.jsonl`: one line per check, with status (`pass`, `fail`, `error`, `na`), points, evidence and the log path.
- `summary.json`: the harness's own totals, before any adjudication, void or judge decision. Read the totals in the top-level README instead.
- `logs/`: one log per check, with every request, response and assert.
- `setup.json`, `state.json`, `proxy_urls.jsonl`, `X7-pairs.jsonl`: harness state.
- `notes/`: what a grader wrote after reading the logs: adjudication of every non-pass, the judges' verdicts, the G1 lane, the void review and the re-score.

Removed before publishing: the fixture file and the raw sweep (database dumps, backups, CLI homes). These held the throwaway passwords, keys and tokens the grader created on stacks it then destroyed. Wherever one of those values appeared in a log, it now reads `<redacted-password>`, `<redacted-key>` or `<redacted-token>`.

Labels: in `exova-run3/notes`, `build-1` is Exova run 3. `build-2`, and the labels `c1` and `r4` in `claude-c2/notes`, are other runs that are not published in this repository.
