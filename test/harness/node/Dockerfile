# check=skip=InvalidDefaultArgInFrom
# The test node: Docker-in-Docker plus the host tools a real node has. NODE_IMAGE is
# the digest-pinned docker:29-dind of internal/nodecfg/images.lock (make node-up).
ARG NODE_IMAGE
FROM ${NODE_IMAGE}
RUN apk add --no-cache nftables xfsprogs xfsprogs-extra util-linux iproute2
COPY node-init.sh /usr/local/bin/node-init.sh
ENTRYPOINT ["/usr/local/bin/node-init.sh"]
