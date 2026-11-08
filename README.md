# sandboxes-gateway

<img src="docs/assets/rheic-shark.png" alt="Rheic shark logo" width="180">


## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-gateway` (previously `github.com/quoiner/sandboxes-gateway`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Status: pre-alpha.

Host network policy gateway. The experimental gvproxy integration supports
IPv4 TCP/UDP CIDR rules and domain-only TCP rules with DNS and TLS SNI checks.
Domain UDP rules require the experimental QUIC capability; without it they are
rejected. Domain denies overlapping a direct IP allow are also rejected.
Experimental IPv6 policy and guest loopback forwarding require an explicit
capability flag; QUIC policy requires its own explicit flag. The default keeps
all of them disabled. HTTP Host/method/path and CONNECT
enforcement are not implemented or verified. Audit failure behavior has not
been fully validated.

Policy DNS queries use the configured upstream; a hostname in that configuration
may require host DNS for bootstrap. Use a numeric upstream address to avoid that
lookup. `policy.Check` evaluates rules locally and does not prove that a DNS
binding exists or that a subsequent TLS connection will pass SNI checks.

The `registryauth` package provides host-side parsing, scoped token exchange,
and restricted transport primitives. These primitives do not authenticate a
sandbox, enforce guest egress, or enable guest registry pulls on their own.

## Boundaries

- separate process from the daemon;
- default deny;
- every deny needs a positive control in tests;
- unsupported paths are explicitly disabled, not silently allowed.


## Gateway manager

`Manager` starts one pinned `gvproxy` process per sandbox with:

- dedicated Unixgram socket;
- default-deny egress policy;
- audit log path;
- policy reload rewrites the config, sends SIGHUP, and verifies the patched gvproxy's appended `egress policy reloaded revision=N` log acknowledgement; a missing acknowledgement stops the gateway and fails closed;
- TCP port forwards;
- deterministic MAC and nerdbox network annotations.

The manager requires a supervisor executable and a patched gvproxy supporting
the owner-lease flag. Without either component gateway startup fails closed.
The matching daemon entry point and gvproxy build patch must be deployed
together; this module alone does not supply a runnable supervisor binary.

Windows work adds a private bearer-token file for the TCP services API, a
kill-on-close process Job Object, and policy reload over the authenticated
services endpoint with an exact revision ACK. `Manager.Start` still fails
closed on Windows: QEMU's network socket is TCP without endpoint
authentication. A bearer token on the separate services API does not
authenticate packet-channel clients.

Current tests cover config rendering, MAC derivation, validation, and safe stop.
An opt-in local test starts and stops a supplied patched gvproxy; it does not
test a VM or establish policy enforcement. It is not part of CI.
