# The wire proxy's image: the static binary built by `make build`
# (CGO_ENABLED=0), nothing else. Build from the repository root after
# `make build`. The node starts it with its table's path as the command.
FROM scratch
COPY bin/pgcap /pgcap
# A soft heap limit well under the container's memory limit: the heap holds the
# connections' copy buffers; the kernel's socket buffers and the runtime take
# the rest of the limit.
ENV GOMEMLIMIT=32MiB
# Its own numeric user, not root and shared with no other container.
USER 65529:65529
CMD ["/pgcap", "/etc/pgcap/pgcap.json"]
