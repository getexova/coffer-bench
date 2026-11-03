# run-build-1-r2 (grader1, full suite, round 2)

1. ssh to gradevm OK on first try (12:52 UTC).
2. grader2 idle: only systemd/sd-pam/catatonit/dbus processes; no podman/conmon/podman-compose/run.py.
3. grader1 store cleaned (stop/rm/pod rm/volume rm/rmi/system prune). It was already empty apart from the pre-pulled postgres:16 (removed by rmi -af). A leftover ~/harness-00dcf74bd482 dir from an earlier run was left untouched (it is not a podman resource).
4. Host prep: podman pull docker.io/library/postgres:16 OK on the first try. Image list: docker.io/library/postgres:16 74d436cb49d3 (459 MB), nothing else.
5. Harness version on the laptop: 4a895ba4d9c6 (matches). Note: the task's context line said "version 00dcf74bd482", but step 5 requires 4a895ba4d9c6, and that is what was used.
6. Bundle sha256 on the VM matches 3ced0952...912be.
7. rsync to ~/harness-4a895ba4d9c6/ rc=0; remote version 4a895ba4d9c6.
8. ~/r2.sh: python3 -I run.py --bundle ~/build-1.bundle --work ~/work-r2 --out ~/out-r2, tee to ~/console-r2.tmp, exit code to ~/r2.exit, then console copied to ~/out-r2/console.log. Started in tmux session r2 at 12:53:45 UTC.
9. run.py exit code 0. summary started 2026-10-29T12:53:45Z, finished 2026-10-29T13:06:00Z (about 12.3 min). partial=false.
10. Copied to results/build-1/r2/. The first rsync was cut off at 2 min by the tool timeout (116 of 217 files); the retry finished with rc=0. Files: 217 local = 217 remote (76 MB).
11. Teardown: podman stop -a; system prune -af --volumes. 0 containers, volumes, pods and images remain; tmux has no server, and there are no grader1 podman processes.

## Results
85 rows: pass 73, fail 7, error 1, na 4.
- fail: F3, X10, X11, O4, X4, X2, A6
- error: S16 (the harness marks it "review, not graded")
- na: G1, E2, E4, E5 (manual)
- verdict NOT SHIPPABLE; blockers_failed [X10, X2]; errors [S16]; p0_pct 89.2; total_points 137.
- verdict_note: "G1 strict/assisted decided manually; SHIP possible only if G1 strict; PROVISIONAL: 1 errors; blockers in error (not passed, not failed): S16"
- No "setup failed at ENV" anywhere.

## Abnormal
- console.log is 0 bytes: run.py wrote nothing to stdout/stderr (the remote console-r2.tmp is also 0 B). The logs are in out/logs/.
- The out dir holds secrets.jsonl and fixture.json (mode 0600, harness output). They were copied as-is and not read.
