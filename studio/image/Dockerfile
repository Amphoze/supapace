# The dashboard's runtime image: the pinned Node base and the build output only — no build
# toolchain, no server source maps, no .env file. Built by studio/build.sh, which supplies
# the context (srv/, the notices, build-record.json) and the two arguments.
ARG NODE_BASE
FROM ${NODE_BASE}
ARG STUDIO_ENV
WORKDIR /app
COPY srv/ /app/
COPY LICENSE NOTICE.supapace THIRD-PARTY-NOTICES /app/
LABEL supapace.studio.env=${STUDIO_ENV}
EXPOSE 3000
# The server itself is the entry point: no shell script at start, and no start shim (upstream's
# loads a .env file the image does not hold).
ENTRYPOINT ["node", "apps/studio/.output/server/index.mjs"]
CMD []
COPY build-record.json /opt/supapace/build-record.json
