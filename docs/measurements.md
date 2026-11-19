# Measurements

What the first release measures, how, and the results. This page fixes each method; the
figures come from runs on the machine stated below. No host name or address is recorded, only
the machine's class (CPU count, memory, kernel and Docker versions, whether it is the test node
or a host install). A figure marked **still open** has not been measured yet.

Machine for every figure on this page (2026-11-19): the test node container on a workstation —
24 cores (one recent x86-64 laptop-class processor), 31 GiB of memory, Linux
7.0, Docker 29.2 on the workstation and 29.10 inside the node; the node container is limited to
4 GiB and its project file system is a loop-backed XFS image.

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

Two runs, each on a project created with the defaults and restarted, the only active project
on the node (run 2 on a second project, after run 1's was deleted and purged):

| Reading (MiB) | Run 1 | Run 2 |
|---|---|---|
| `current` at start | 62 | 62 |
| `max_cur`, `max_anon` over 5 idle minutes | 78, 11 | 89, 11 |
| `max_cur`, `max_anon` under 72 sessions | 512, 131 | 512, 131 |
| `file` at the end of the load | 338 | 338 |
| transactions per second, failed transactions | 3,351, 0 | 4,192, 0 |

Under load `memory.current` reaches the 512 MiB limit and stays there: the rest is page cache
(`file`), which the kernel reclaims; the servers' own memory (`anon`) peaks at 131 MiB with 72
sessions, about a quarter of the limit. No run was killed for memory and no transaction
failed.

## Operation times

Question: how long the operator waits for a create (with the two-phase first boot), a
restart and a delete.

Method: on a freshly started node, ten `supapace project create` in sequence, each with its
own issuer key set; the node admits four projects, so from the fifth on the oldest project is
deleted and purged before the next create. Then five `supapace project restart` of one project
without changes. The time is the wall time of the CLI call, from its start to its `done`
(the CLI waits for the operation), read inside the node from `/proc/uptime` (10 ms steps).

| Operation | Runs | Median (s) | Worst (s) |
|---|---|---|---|
| `project create` | 10 | 21.1 | 36.7 |
| `project restart` | 5 | 5.0 | 6.0 |
| `project delete` | 6 | 3.3 | 4.5 |
| `project purge` (right after the delete) | 6 | 2.3 | 4.5 |

The ten creates took 29.1, 27.2, 36.7, 23.1, 25.1, 19.1, 16.1, 15.1, 8.5 and 8.5 s, in that
order: the first creates on a freshly started node are the slowest.

## Daemon start

Question: how soon a restarted daemon answers on its admin socket and routes every project
again, without restarting any tenant container.

Method: four active projects; `kill -9` of `supapaced serve`, which the node's supervisor
starts again after one second. Measured inside the node from the moment the new
`supapaced serve` process is first seen (polled every 20 ms): until a `supapace project list`
answers, and until the route file, rewritten after the start (every route is set draining at
start), lists every project active again. Three runs.

| Reading | Run 1 | Run 2 | Run 3 |
|---|---|---|---|
| start → admin socket answers | 0.34 s | 0.37 s | 0.36 s |
| start → every route active | 1.02 s | 1.05 s | 0.99 s |

## Idle memory of the platform's own processes

Question: what the platform itself uses on a node at rest.

Method: four active projects, untouched for five minutes; `memory.current` (and the `anon`
line of `memory.stat`) of each container's cgroup. The daemon runs in the node's own
supervisor cgroup together with other processes, so its figure is its resident set
(`VmRSS`, and `RssAnon`) instead.

| Process | `memory.current` (MiB) | `anon` (MiB) |
|---|---|---|
| gateway (`sp-gateway`) | 11.4 | 4.1 |
| control-plane database (`sp-cp-db`) | 113.7 | 12.7 |
| one PostgREST container | 6.1 | 5.5 |
| daemon (`supapaced serve`), resident set | 20.8 | 8.3 |

For comparison, one idle cluster container read 63.9 MiB (`anon` 11.4) at the same moment.

## Gateway capacity

Question: the gateway's memory at its limits, against its 768 MiB container
(`GOMEMLIMIT=460MiB`).

Method: the gateway at its connection and in-flight limits (2,048 connections, 64 per source;
2,048 proxied requests in flight, 128 per project), with request bodies up to the 8 MiB cap,
over HTTP/1.1 and HTTP/2; the container's `memory.peak` read as above. The repository has no
script for this run yet. The constants are in `internal/gateway/server.go` and `limit.go`.

| Reading | Value |
|---|---|
| `memory.peak` at the limits | still open |
| an 8 MiB upload at 100 ms and 200 ms round trip | still open |

Still open because the run needs what the repository does not have: a load client that holds
2,048 connections over HTTP/1.1 and HTTP/2 from at least 32 source addresses (64 per source)
and streams 8 MiB bodies; an upstream stand-in that keeps 128 requests per project in flight
(PostgREST answers them too quickly to hold them); and a delayed link for the 100 ms and 200 ms
round trips, which needs a traffic-control queueing discipline on the host.
