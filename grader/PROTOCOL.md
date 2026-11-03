# Coffer bench: run protocol

Three files:
- `SPEC.md`: the only thing a builder sees. Identical bytes in every arm.
- `GRADER.md`: the hidden acceptance suite. A builder must never be able to read it.
- `PROTOCOL.md`: this file. It decides whether the result means anything.

## Before any run

1. **Install a compose provider on the build/grading machine** (none is installed today: `podman compose` fails with "looking up compose provider failed"). Use `sudo dnf install podman-compose` or the docker-compose plugin. Also install `osv-scanner`, `gitleaks` and `mitmproxy` for grading. A builder that loses hours to a missing host tool is measuring the machine, not the builder.
2. **Freeze.** `sha256sum SPEC.md GRADER.md > FROZEN.sha256` and note the time. No edits after the first run starts. If the spec has a hole, it stays a hole in every arm.
3. **Hide the grader.** Claude Code can read anything its OS user can read, including `~/.claude/projects/*/` transcripts, and the transcript of the session that wrote GRADER.md quotes it. So:
   - Run every arm as a **separate OS user** (e.g. `useradd bench`) with an empty home, a fresh login, no `CLAUDE.md`, no memory, no plugins, no MCP servers beyond the defaults.
   - Then `gpg -c GRADER.md && shred -u GRADER.md` until grading time, and keep the plain copy off the bench user's filesystem.
4. Each arm starts in an **empty directory** containing only `SPEC.md`.

## Arms

| Arm | Harness | Models |
|---|---|---|
| A | Claude Code, ultracode workflow | Opus 5.5, default effort |
| B | Exova Team | Cost-Saving preset (GLM-5.3 build/plan roles, GLM-5.3-Flash Reviewer + vision + research). Pin the per-session Team Pipeline security review to **auto-fix**; it defaults to `auto`, which lets the CEO choose `off`. |
| C (strongly recommended) | Exova Team | The same Claude model as A, if the gateway can serve it. Same pipeline settings as B. |

Each arm runs its product's strongest documented configuration, and the exact settings are written into the report. Defaults-vs-defaults is also a valid comparison, but choose one rule before the first run and apply it to every arm.

A vs B alone mixes two variables: harness and model. If B loses, you cannot tell which one lost. C separates them: A vs C is the harness, C vs B is the model. Without C, the only claim the result supports is "Exova on open-source models vs Claude Code on Opus", which may be the claim you want, but say it that way.

## The prompt (identical except the A-arm keyword)

```
Read SPEC.md in this directory and build Coffer exactly to it, in this directory, as a git repository.
Work autonomously to the "Done means" bar in the spec. You will receive no further input.
```

Arm A prepends `ultracode ` so the workflow engages. Nothing else differs.

## During the run

- **No steering.** Every question from a builder gets the same reply, verbatim: `Decide, record it in docs/DECISIONS.md, and continue.` Count the questions.
- **Early stops.** If a builder ends its turn without declaring done and without asking anything, reply verbatim `Continue.`, at most 3 times per arm. The 4th stop ends the run. Count them as interventions.
- Permission prompts, Exova's plan sign-off and intake answers: approve mechanically, never edit the plan, and log each one.
- **Caps** (same for every arm): 10 h wall clock; $300 spend as a runaway guard. Record which arm hit which cap.
- **Stop** when the builder declares done, or at a cap. The last commit on the default branch is the submission.

## Record (unscored, reported next to the verdict)

Wall clock; cost and tokens; number of human interactions and what each was; agents spawned; commits; whether the builder ran its own clean-clone check before declaring done.

**Cost source per arm:**
- Exova arms: the gateway's `llm_requests` ledger.
- Arm A: the usage page of a Console workspace used only for this run.

Claude Code's transcripts can't serve as Arm A's meter. Workflow and subagent records on this machine log `input_tokens` only, so `usage.py` prices just the complete records. The two meters differ, and the report must say so.

## Grading

1. Someone other than the person who watched the runs renames the repos `build-1` / `build-2` (or a coin flip is recorded before cloning).
2. Fresh OS user, `git clone` of each repo, run GRADER.md top to bottom in the same order for both.
3. Void any check that fails on both arms and turns out to be a spec or grader fault. Decide this **before** unblinding.
4. Unblind, then publish both reports side by side, including the voids and any assisted-lane fix.

## Reading the result

One run per arm is a sample of one, and agent runs vary a lot. If the verdicts differ by a tier, that is a signal. If they are within ~10 P0 points, run each arm a second time before drawing a conclusion.
