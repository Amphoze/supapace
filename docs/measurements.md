# Measurements

What the first release measures, how, and the results. Every figure below is **to be
measured**: this page fixes the method; a run on a stated machine fills in the numbers. No
host name or address is recorded, only the machine's class (CPU count, memory, kernel and
Docker versions, whether it is the test node or a host install).

## Cluster memory (`test/measure/cluster_mem.sh`)

Question: how much memory one project's cluster container uses idle and under a busy
workload, against its 512 MiB limit.

Method:

1. A node (`make node-up`) with one active project created with the defaults; then
   `supapace project restart REF`, so that the run starts on a new container.
2. `make measure` (parameters `REF`, `IDLE`, `LOAD`, `CLIENTS`, for example
   `make measure IDLE=300 LOAD=300`). Defaults: 300 s idle, then 300 s of load with 72
   concurrent sessions. Ctrl-C stops the run: the target sends TERM to the script in the node,
   which removes the client container and the database.
3. Phases: start; `IDLE` seconds untouched; `pgbench -i` (scale 10, about 160 MiB); `LOAD`
   seconds of load. The script reads the cgroup v2 files of `pg-<ref>`. During the idle and
   load phases it samples `memory.current` and the `anon` line of `memory.stat` every second
   and reports each phase's highest values (`max_cur`, `max_anon`), with the readings at the
   end of the phase (`current`, `anon`, `file`) and `memory.peak` (`peak_all`).
4. The load is `pgbench` from the cluster image, built-in scripts `tpcb-like` (read/write)
   and `select-only` weighted 3:7, `-j 4`, as the role `postgres` in a database of its own
   (`sp_measure`, dropped at the end). The client runs in its own container in the cluster's
   network namespace, so its memory is not charged to the cluster.

Reading the results: `file` is page cache, which the kernel reclaims under pressure, so
`memory.current` close to the limit after data has been read is expected; `anon` is the
servers' own memory, and the figure to compare between idle and load. `memory.peak` is the
highest value since the container started and is never reset during the run (a reset needs
Linux 6.12 and a file descriptor kept open between the reset and the read, which the script's
shell cannot do): after `pgbench -i` it already includes the page cache that run filled, so
`peak_all` says nothing about the load phase alone; the sampled `max_cur` does, at a one-second
resolution. A shortened run (`IDLE=10 LOAD=15`) checked that the script works; its figures are
not results.

| Reading (MiB) | Value |
|---|---|
| `current` at start | to be measured |
| `max_cur`, `max_anon` over 5 idle minutes | to be measured |
| `max_cur`, `max_anon` under 72 sessions | to be measured |
| `file` at the end of the load | to be measured |
| transactions per second, failed transactions | to be measured |

Machine: to be recorded.

## Gateway capacity

Question: the gateway's memory at its limits, against its 768 MiB container
(`GOMEMLIMIT=460MiB`).

Method: the gateway at its connection and in-flight limits (2,048 connections, 64 per source;
2,048 proxied requests in flight, 128 per project), with request bodies up to the 8 MiB cap,
over HTTP/1.1 and HTTP/2; the container's `memory.peak` read as above. The repository has no
script for this run yet. The constants are in `internal/gateway/server.go` and `limit.go`.

| Reading | Value |
|---|---|
| `memory.peak` at the limits | to be measured |
| an 8 MiB upload at 100 ms and 200 ms round trip | to be measured |

Machine: to be recorded.

