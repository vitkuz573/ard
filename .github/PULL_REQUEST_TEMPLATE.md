## The problem

<!-- What is broken, and what the change does about it. Link the issue if there is one. -->

## Why

<!--
The reasoning, not the summary of the diff. A reviewer can read the diff; they
cannot read why you rejected the three other approaches.

If something here was measured rather than assumed, say so and say how. In this
codebase several wrong turns survived because they were plausible, and the
project convention is to record the measurement that killed them.
-->

## How it was tested

<!--
Be specific about the device and the topology. ARD failures hide in the join
between two machines, so "tested locally" is not an answer.

- [ ] `go test ./...`
- [ ] `scripts/e2e-local.sh` against the mock device
- [ ] Real device (state which one, and whether it is behind CGNAT)
- [ ] Gateway deployed with `scripts/deploy.sh` and verified

If something was **not** tested, say that instead of leaving it unchecked. An
untested change described as tested is worse than an untested change.
-->

## Checklist

- [ ] `gofmt -l cmd internal test` is empty
- [ ] `go vet ./...` is clean
- [ ] `go test -race ./...` passes
- [ ] No new dependency without a note on why the standard library is not enough
- [ ] No IP address, hostname, serial number, certificate or key anywhere in the
      diff, including in comments, test fixtures and commit messages
- [ ] Comments explain *why*, not *what*
- [ ] Documentation updated if behaviour or a command changed