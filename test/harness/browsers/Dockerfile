# The browser harness: Chromium, Firefox and WebKit from the pinned upstream
# browser-automation image, the automation package at the same release, the
# NSS tools that install a CA for the first two, and run.mjs. Build:
#   docker build -t supapace-browsers:local -f test/harness/browsers/Dockerfile test/harness/browsers
# Run with every capability dropped, no-new-privileges and a read-only root:
# the only writable place is a tmpfs at /tmp, where run.mjs builds the trust
# stores of the run (test/browser runs it). The build is the only step that
# needs the network: the NSS tools at an exact version from the release
# pocket of the base image's suite, and the automation package from the
# committed lockfile (integrity hashes) with no install scripts.
FROM mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
ARG NSS_TOOLS=2:3.98-1build1
RUN apt-get update && apt-get install -y --no-install-recommends "libnss3-tools=$NSS_TOOLS" && \
	test "$(dpkg-query -W -f '${Version}' libnss3-tools)" = "$NSS_TOOLS" && rm -rf /var/lib/apt/lists/*
WORKDIR /opt/harness
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund --no-update-notifier && npm ls playwright
# WebKit reads the system store: the image's bundle is kept beside run.mjs and
# the store becomes a link into /tmp, which run.mjs writes at the start of a
# run (the bundle, plus the CA the run trusts).
RUN cp /etc/ssl/certs/ca-certificates.crt /opt/harness/system-ca.crt && \
	ln -sf /tmp/trust/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY run.mjs /opt/harness/run.mjs
USER pwuser
ENV HOME=/tmp/home
ENTRYPOINT ["node", "/opt/harness/run.mjs"]
