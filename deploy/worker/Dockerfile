# check=skip=InvalidDefaultArgInFrom
# The backup worker image: pgBackRest built from source on Alpine, with no
# PostgreSQL server in it. Built by `make images`: the build context is the
# directory holding the source archive, and the three arguments come from
# internal/nodecfg/images.lock (worker_base, worker_source).
ARG WORKER_BASE

FROM ${WORKER_BASE} AS build
# Versions are pinned, Alpine's package revision (-rN) is not: the release replaces a revision
# in place. An apk "unable to select" error means a VERSION moved: look at it, then bump the pin.
RUN apk add --no-cache gcc~15.2.0 musl-dev~1.2.6 meson~1.11.1 pkgconf~2.5.1 \
	libpq-dev~18.7 openssl-dev~3.5.9 libxml2-dev~2.13.9 zlib-dev~1.4 lz4-dev~1.10.0 \
	zstd-dev~1.6.0 bzip2-dev~1.0.8 yaml-dev~0.2.5
ARG WORKER_SRC
ARG WORKER_SRC_SHA256
COPY ${WORKER_SRC} /tmp/src.tar.gz
# The archive's checksum is checked before anything unpacks it; an empty or
# wrong WORKER_SRC_SHA256 fails here.
RUN echo "${WORKER_SRC_SHA256#sha256:}  /tmp/src.tar.gz" | sha256sum -c - && \
	mkdir /src && tar -xzf /tmp/src.tar.gz -C /src --strip-components 1 && \
	meson setup /build /src --buildtype=release -Dlibssh2=disabled -Dlibzstd=enabled && \
	ninja -C /build && strip /build/src/pgbackrest

# The one binary and the libraries it links (libpq brings no server). The
# postgres user and group (70) are named, so a backup manifest records the
# owner by name. No /etc/pgbackrest/pgbackrest.conf: every option comes from
# the job's environment.
FROM ${WORKER_BASE}
RUN apk add --no-cache libpq~18.7 libssl3~3.5.9 libcrypto3~3.5.9 libxml2~2.13.9 xz-libs~5.8.4 \
	zlib~1.4 lz4-libs~1.10.0 zstd-libs~1.6.0 libbz2~1.0.8 && \
	echo 'postgres:x:70:70:postgres:/var/lib/postgresql:/sbin/nologin' >>/etc/passwd && \
	echo 'postgres:x:70:' >>/etc/group
COPY --from=build /build/src/pgbackrest /usr/bin/pgbackrest
