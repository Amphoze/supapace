# The gateway image: the static binary built by `make build` (CGO_ENABLED=0),
# nothing else. Build from the repository root after `make build`.
FROM scratch
COPY bin/gateway /gateway
# A soft heap limit under the container memory limit (768 MiB), so the GC
# works harder before the kernel kills the process. The rest of the limit is
# for socket buffers, kernel memory and the runtime's own overshoot. Socket
# buffers are fixed per socket in the code: about 128 MiB when every client
# connection floods requests (2,048 x 64 KiB received); only if clients and
# upstreams both stall with every buffer full could they reach 512 MiB.
ENV GOMEMLIMIT=460MiB
# Its own numeric user, not root and shared with no other container.
USER 65531:65531
EXPOSE 8443 8080
ENTRYPOINT ["/gateway"]
