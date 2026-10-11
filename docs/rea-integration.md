# REA integration (experimental, opt-in)

Upstream: https://github.com/morluto/rea (MIT). REA is an external dependency;
no upstream code is vendored.

## Install and diagnose

REA requires supported Node.js (22.19+, 24.11+, or 26+) and npm:

```sh
npm install --global rea-agents
rea setup
rea doctor
```

Review setup changes and choose only the agents/providers you want. Deep native
inspection requires a configured Hopper, Ghidra, or IDA provider. Static JS/Electron
inspection needs only Node/npm. Pin an exact REA version for reproducible deployments.

## ReverseLab adapter

The optional Python module `reverselab.rea_adapter` exposes
`status()` and `analyze(path, mode="javascript"|"native", timeout=120)`.
Example:

```python
from reverselab.rea_adapter import status, analyze
print(status())
result = analyze("/absolute/path/to/application.asar", mode="javascript")
print(result["evidence"])
```

This first increment is **not wired into the web upload route or UI**. This is
intentional: REA can launch external analysis providers and some REA commands
can observe or run targets. A future UI integration must use a dedicated opt-in
job queue, allowlisted static workflows, resource limits, artifact isolation,
explicit confirmation before dynamic operations, and structured evidence display.

The adapter passes the target as a subprocess argument (never through a shell),
validates the mode and timeout, and raises errors for missing tools, failed
commands or non-JSON output. It does not install REA, launch a target directly,
or send binary content to an LLM.

Run tests: `python -m unittest discover -s tests -v`

Validation remains pending for a real REA installation with a controlled
JavaScript/Electron fixture and a configured native analysis provider.
