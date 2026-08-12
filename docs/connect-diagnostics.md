# Android TCP connect diagnostics

Anettrace `v0.5.0` adds a capability-gated diagnostic path for outbound TCP
connection attempts on rooted Android devices. The host-side entry point is:

```sh
python3 tools/diagnose_android_connect.py \
  --package com.example.app \
  --binary /path/to/anettrace \
  --trace-processor /path/to/trace_processor_shell \
  --out /path/to/report
```

The command performs preflight checks, resolves the package to an Android UID,
starts a bounded device capture, correlates each `connect()` attempt with its
socket and kernel evidence, and writes a report bundle. The target application
does not need an SDK or source change.

## Support contract

Android 15 and newer are the target platform range, but an Android or kernel
version alone does not imply support. Every session checks the actual device
for root access, BTF, tracefs, Perfetto, required tracepoints, and usable attach
backends before collecting data.

The first reference configuration is:

- PKC130;
- Android 17 / SDK 37;
- AArch64 Linux 6.6.118;
- root ADB shell with SELinux enforcing;
- KPROBE/KRETPROBE, raw syscall tracepoints, BTF, tracefs and Perfetto.

This reference kernel does not provide the complete fentry/fexit path. The
diagnostic therefore uses raw syscall events for the `connect()` boundary,
KPROBE/KRETPROBE for socket association, and stable kernel tracepoints for TCP
state, retransmission, reset, drop and scheduling evidence.

Maintainers validate the three release outcomes with the AArch64 workload from
the Android Actions artifact. The gate runs each scenario three times and keeps
only privacy-filtered reports:

```sh
python3 -m venv /tmp/anettrace-connect-venv
/tmp/anettrace-connect-venv/bin/pip install -r tools/requirements-perfetto.txt
/tmp/anettrace-connect-venv/bin/python tools/validate_android_connect.py \
  --package com.example.app \
  --binary /path/to/anettrace \
  --workload /path/to/anettrace-connect-workload \
  --trace-processor /path/to/trace_processor_shell \
  --out /path/to/acceptance
```

`success` and `refused` use loopback and are deterministic. `timeout` uses a
numeric non-responsive address with bounded TCP retry settings; the gate fails
instead of rewriting another observed errno as a timeout.

The release soak uses the same workload for a controlled 30-minute success
stream. It compares a short pre-capture baseline with traced throughput and
records collector CPU, peak RSS, event-file growth, lost events, truncation and
verified device cleanup:

```sh
/tmp/anettrace-connect-venv/bin/python tools/soak_android_connect.py \
  --package com.example.app \
  --binary /path/to/anettrace-0.5.0-android-arm64-dual \
  --workload /path/to/anettrace-0.5.0-connect-workload-android-arm64 \
  --trace-processor /path/to/trace_processor_shell \
  --out /path/to/soak
```

The formal gate does not accept a soak shorter than 1800 seconds. It requires a
valid report, zero lost events, no truncation, at least two resource samples and
verified capture cleanup. Throughput change is recorded as evidence rather than
silently compared with an undocumented threshold.

If a core probe or event-integrity requirement is missing, Anettrace produces
an `invalid` report without a root-cause verdict. Missing optional evidence
produces a `degraded` report with the unavailable capability listed.

Preflight also reads Perfetto's protobuf service state through `--query-raw`.
If another started Perfetto session exists, the diagnostic refuses to start; it
does not stop, attach to, or alter that session. Retry only after its owner has
finished it. Active global or per-instance tracefs event collection is treated
the same way; merely having an idle tracefs instance is not a conflict.

## Diagnostic unit and outcomes

The unit of analysis is one outbound TCP connect attempt associated with one
session-scoped socket instance. Blocking and nonblocking connects are supported.
`EINPROGRESS` is a pending state, not a failure; the attempt remains open until
socket state and observable `SO_ERROR` evidence resolve it or the capture ends.

Every attempt has exactly one outcome:

| Outcome | Meaning |
| --- | --- |
| `success` | The connect completed successfully. |
| `local_rejection` | A versioned errno mapping identifies a local parameter, resource or policy rejection. |
| `network_unreachable` | A versioned errno mapping identifies a network, route or host reachability failure. |
| `peer_refused` | `ECONNREFUSED`, or a reset reliably associated with the socket while it is connecting. |
| `timeout_no_response` | `ETIMEDOUT` was observed; SYN and retransmission data are supporting evidence. |
| `kernel_drop` | A kernel drop was precisely associated with the attempt's SYN lifecycle. |
| `interrupted_or_cancelled` | A direct error or a proven close/process exit cancelled the pending attempt. |
| `incomplete_or_unknown` | The capture ended pending, the errno is unknown, or evidence is insufficient. |

Evidence strength is `direct`, `correlated`, or `insufficient`. A report may
list retransmission, RTT and scheduler measurements as contributing evidence,
but those measurements do not become a root cause without the required direct
or correlated evidence.

The first release intentionally does not apply a hidden or public latency
threshold. It reports measured durations and events without declaring that a
stage is "slow".

## Privacy contract

By default the report contains the network metadata needed for diagnosis:
UID/TID, anonymous application and socket IDs, addresses, ports, protocol,
interface/network context, monotonic timing, errno and capability information.

When packet evidence is available, `network_context` also reports interface,
network namespace and the Android fwmark-derived `net_id`, explicit-selection
bit and `protected_from_vpn` bit. The latter means the socket was marked to
bypass VPN capture; it does not by itself prove that a VPN caused an outcome.

By default it does not persist package names, shared-UID package candidates,
device serials, fingerprints, account data or the device application list.
`--include-package` opts the current report into storing the selected package
and shared-UID candidates.
Shared-UID detection queries only packages assigned to the selected UID; it
does not enumerate the full device package list.

The v1 collector does not read or store payloads, URLs, headers, SNI, DNS query
names or DNS response content. It does not install a TLS probe.

## Bounded collection

The default capture is limited to 120 seconds and a 512 MiB report budget. The
device enforces its own limits so an ADB interruption cannot leave an unbounded
collector. The default Perfetto profile is `sched`; the broader `full` profile
is opt-in.

Each run uses a unique device directory. After verified pull and hashing, the
directory is removed unless `--keep-device-artifacts` is explicit. The command
does not automatically run `adb root`, `su`, or Magisk commands, and it does not
stop another tracing session. Unsafe trace-resource conflicts fail preflight.

The collector binary is supplied with `--binary` or by the matching release
bundle. Its architecture, version, Git commit and SHA-256 are recorded before
use. Trace Processor is supplied with `--trace-processor` or found on `PATH`;
its version and SHA-256 are also recorded. The command never downloads a tool at
runtime.

If ADB disconnects, the invalid report manifest preserves the non-sensitive
12-hex capture session ID when it was created. After reconnecting, inspect,
pull, or explicitly clean only that session:

```sh
python3 tools/diagnose_android_connect.py \
  --recover-session 0123456789ab --recover-action inspect
python3 tools/diagnose_android_connect.py \
  --recover-session 0123456789ab --recover-action pull --out /path/to/recovery
python3 tools/diagnose_android_connect.py \
  --recover-session 0123456789ab --recover-action cleanup
```

Recovery never scans unrelated device directories and never persists the ADB
device selector.

## Report bundle

The user chooses an output directory. The directory is created with mode `0700`
and files with mode `0600`:

- `report.md`: human-readable verdict, evidence and Perfetto drill-down notes;
- `report.json`: public `anettrace.connect-diagnostics.v1` machine contract;
- `manifest.json`: versions, capabilities, filters, privacy flags and integrity;
- `trace.pftrace`: the evidence timeline;
- `session.log`: redacted orchestration and failure diagnostics;
- `SHA256SUMS`: hashes of the stable report files.

Report status is `valid`, `degraded`, or `invalid`. Even an invalid session keeps
its redacted manifest and log, but it does not claim a root cause.

## Explicit non-goals for v1

- DNS transaction or encrypted-DNS diagnosis;
- QUIC/HTTP3;
- HTTP/RPC request timing after a TCP connection is established;
- payload or TLS plaintext capture;
- an always-on flight recorder or hidden history database;
- prebuilt Linux release binaries;
- automatic migration to the independent `android-tracing` product branch.

The JSON schema in `schemas/connect-diagnostics-v1.schema.json` is the normative
report interface. The stable Trace Processor query is
`tools/perfetto_sql/connect_diagnostics.sql`. Fixtures and SQL contract tests
are part of CI and must stay aligned with this document.
