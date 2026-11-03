# G1 — build-1 (grader1@gradevm)

Result: **assisted-pass**. Strict lane FAILED at step 2 (up.sh hung). One fix was made in the assisted lane: a prerequisite image pull. After it, `secrets get` returned the value byte-exact 19.97 min after T0.

## Environment
- gradevm: Fedora 44, rootless podman 5.8.9, podman-compose 1.6.0 via `docker compose`, short-name-mode enforcing. Non-interactive ssh, stdin from /dev/null, no TTY.
- No sudo. Go not installed. build.sh fell back to its own container image.
- Before step 1, `ps -u grader2 -o pid,comm` showed only systemd, (sd-pam), catatonit and dbus-broker. No podman, conmon, podman-compose or run.py was running, so grader2 was idle.
- No earlier attempt existed: ~/g1-build, ~/g1-logs and ~/g1-T0 were all absent.

## Cold store (step 1)
- Before: images = `docker.io/library/postgres:16 74d436cb49d3`. No containers. One volume, `ebee91cc5aba...` (left over from setup).
- I ran podman stop/rm/pod rm/volume rm/rmi/system prune -af --volumes, then `rm -f ~/.config/containers/registries.conf.d/000-coffer-grade-postgres.conf`. XDG_CONFIG_HOME is unset.
- After: `podman images -a -q`, `ps -a -q` and `volume ls -q` all printed nothing.
- `ls -la ~/.config/containers/registries.conf.d/` printed: `ls: cannot access '/home/grader1/.config/containers/registries.conf.d/': No such file or directory`. The `test ! -e` check passed.
- coldStoreEmpty = true

## Timeline (UTC; T0 = 10:22:57Z, the clone)
| step | command | rc | wall | key output |
|---|---|---|---|---|
| T0 | git clone ~/build-1.bundle ~/g1-build | 0 | 0.05 s | Cloning into ... |
| 1 | ./scripts/init-env.sh | 0 | 0.03 s | Wrote .env (mode 0600) ...; admin password <redacted> |
| 2 | ./scripts/up.sh | HUNG (killed) | 1048 s (10:23:38–10:41:06) | `Error: short-name resolution enforced but cannot prompt without a TTY`; `Error: "g1-build_db_1" is not a valid container, cannot be used as a dependency`; `podman-compose up -d` then hung with no log output after 10:24:59 |
| A | podman pull docker.io/library/postgres:16 (assisted fix) | 0 | 20 s | image 74d436cb49d3 |
| 2 (rerun) | ./scripts/up.sh | 0 | 8.83 s | Coffer is ready (after 1 s). |
| 3 | ./scripts/build.sh | 0 | 14.7 s | Built ./bin/coffer ... with the golang:1.27.3-bookworm container via podman. |
| 4 | sed ... .env \| ./bin/coffer login --email admin@coffer.local | 0 | 0.23 s | Logged in as admin@coffer.local |
| 5 | printf '<redacted>\n' \| coffer admin org create acme --owner-email owner@acme.test | 0 | 0.19 s | Created organization acme |
| 6 | printf '<redacted>\n' \| coffer login --email owner@acme.test | 0 | 0.20 s | Logged in; must change password |
| 7 | printf '<redacted>\n<redacted>\n' \| coffer passwd | 0 | 0.26 s | Password changed. |
| 8a | coffer project create demo | 0 | 0.12 s | Created project demo |
| 8b | coffer env create dev -p demo (&&) | 0 | 0.12 s | Created environment dev in demo |
| 9 | printf 'hello-from-coffer' \| coffer secrets set GREETING -p demo -e dev | 0 | 0.12 s | Set GREETING (version 1) |
| 10 | coffer secrets get GREETING -p demo -e dev | 0 | 0.12 s | `hello-from-coffer`, 17 bytes, no newline; cmp byte-exact. Done at 10:42:55Z |

Steps ran inside tmux on the VM through ~/g1-step.sh, with logs in ~/g1-logs/. Each step ran as a fresh `bash -c` in ~/g1-build. Steps 8a and 8b ran in sequence and would have stopped on the first failure, which keeps the `&&` behaviour.

On step 2: I first saw the db error on a poll at about 10:32. The log mtime check at 10:40:47 showed no output since 10:24:59, more than 10 minutes, so I killed the process group (SIGTERM). At that point `podman ps -a` showed no containers and /readyz returned 000.

## Strict result
FAIL at step 2. `db` uses the unqualified short name `postgres:16`. With enforcing mode, no TTY and an empty store, podman cannot resolve it. podman-compose then failed to create `server` (it depends on `db`) and hung instead of exiting, and up.sh never reached its 180 s readyz timeout.

## Assisted lane
- Fix (one, prerequisite): `podman pull docker.io/library/postgres:16`. No file was edited and no host or registries config was changed. I re-ran step 2 with the existing state and continued the quickstart verbatim.
- assistedPulls: docker.io/library/postgres:16
- Assisted pass at 19.97 min after the original T0.

## G2 observation
- Strict: up.sh hung. I killed it after 1048 s with no rc; /readyz on http://127.0.0.1:8420 returned 000.
- After the assisted pull: up.sh rc 0 in 8.83 s, /readyz = 200 straight after.

## Teardown
- `./scripts/down.sh`: rc 0 ("Stack stopped. The db_data volume was kept ...").
- Then podman stop -a, rm -af, pod rm -af, volume rm -af, system prune -af --volumes.
- After: `podman images -a -q`, `podman ps -a -q` and `podman volume ls -q` all printed nothing. teardownEmpty = true. No tmux sessions are left.
- Left on the VM: ~/g1-build, ~/g1-logs (they hold the bootstrap password, so not copied back), ~/g1-T0, and the helper scripts ~/g1-step.sh, ~/g1-seq.sh and ~/g1-steps.txt (the verbatim step list).
