# Developer entry points. See the targets below; the reach suite runs on the node as root.
SHELL := bash
GO ?= go
BIN := bin
# Node container name; set NODE to run several harnesses side by side. Its two
# volumes are $(NODE)-docker and $(NODE)-state; the node image is shared.
NODE ?= sp-node
NODE_IMAGE := supapace-node:local
NODE_BIN := /opt/supapace/bin
GATEWAY_IMAGE := supapace-gateway:local
# The local tag of the backup worker image; whatever it is, the archive names
# the image supapace-worker:local, as the node refers to it (likewise the gateway).
WORKER_IMAGE := supapace-worker:local
# The local tags of the wire proxy's image and of the browser harness's; their
# archives name them supapace-pgcap:local and supapace-browsers:local.
PGCAP_IMAGE := supapace-pgcap:local
BROWSERS_IMAGE := supapace-browsers:local
IMAGE_CACHE ?= $(HOME)/.cache/supapace/images
# DASH=1: a dashboard node. make images also builds the wire proxy's image and
# requires the Studio archive (make studio); make node-up gives the node a studio
# domain (STUDIO_DOMAIN) and 6 GiB, and the node loads the archives of
# $(IMAGE_CACHE)/dash, which only a dashboard node needs. The image-cache script
# reads SP_DASH for the images of the lock that only a dashboard node needs.
DASH ?=
STUDIO_DOMAIN ?= studio.test
# The node's memory limit in GiB; node-up and node-bare refuse to start the node
# unless this machine has that and 2 GiB more available.
NODE_MEM ?= $(if $(DASH),6,4)
ifneq ($(DASH),)
export SP_DASH := 1
endif
BROWSERS_TAR = $(IMAGE_CACHE)/browsers/supapace-browsers.tar
LOCK := internal/nodecfg/images.lock
# $(call lock_ref,KEY): name@digest of an images.lock entry; $(call lock_field,KEY,N):
# its tag (1) or digest (2).
lock_ref = $(shell sed -n 's/^ *"$(1)": *{"tag": *"\([^":]*\)[^"]*", *"digest": *"\([^"]*\)".*/\1@\2/p' $(LOCK))
lock_field = $(shell sed -n 's/^ *"$(1)": *{"tag": *"\([^"]*\)", *"digest": *"\([^"]*\)".*/\$(2)/p' $(LOCK))
# The harness base image; passed to the node Dockerfile as the build argument
# NODE_IMAGE (ARG before FROM).
NODE_BASE = $(call lock_ref,node)
# The worker image's base and pgBackRest's source archive (kept in $(IMAGE_CACHE)/src).
WORKER_BASE = $(call lock_ref,worker_base)
WORKER_SRC = $(call lock_field,worker_source,1)
WORKER_SRC_SHA256 = $(call lock_field,worker_source,2)
WORKER_SRC_URL := https://github.com/pgbackrest/pgbackrest/archive/refs/tags/release/2.58.0.tar.gz
# The object-store stand-in beside a test node, unless SP_OFFSITE=0: pulled by
# make images into this machine's Docker, never into a node.
S3_IMAGE = $(call lock_ref,s3_standin)
SP_OFFSITE ?= 1
include test/harness/s3/lab.env
# The node's lab slot: by default the node name's checksum mod 250, plus 1. Its two
# networks are 10.215.<slot>.0/25 and 10.215.<slot>.128/25, the stand-in at .10 and
# .138, the node at .5 and .133. Pass S3_SLOT=<n> (0..255) when two nodes collide.
S3_SLOT ?= $(shell printf %s '$(NODE)' | cksum | awk '{print $$1 % 250 + 1}')
S3_NET1 = 10.215.$(S3_SLOT).0/25
S3_NET2 = 10.215.$(S3_SLOT).128/25
S3_ADDR1 = 10.215.$(S3_SLOT).10
S3_ADDR2 = 10.215.$(S3_SLOT).138
S3_NODE1 = 10.215.$(S3_SLOT).5
S3_NODE2 = 10.215.$(S3_SLOT).133
S3_LAB = S3_SLOT=$(S3_SLOT) S3_NET1=$(S3_NET1) S3_NET2=$(S3_NET2) S3_ADDR1=$(S3_ADDR1) S3_ADDR2=$(S3_ADDR2) \
	S3_NODE1=$(S3_NODE1) S3_NODE2=$(S3_NODE2)
REACH_FLAGS := -test.v -test.parallel 1
REACH_ARGS ?=

# Suite reset, run on the node before and after every reach run whatever its exit
# status: drop the drift hold and any failpoint, reload our tables, remove every scratch object
# labelled supapace.test=1, every probe listener a killed run left behind (they
# keep scratch namespaces alive) and the routed neighbour's veth, and the second
# source address of test 17. A failed rules
# load stops at once; any other failed step fails the reset after the rest has run.
# $(1) is the supapaced binary.
reset = s=0; rm -f /run/supapace/failpoint || s=1; $(1) nft load || exit 1; \
	docker ps -aq --filter label=supapace.test=1 | xargs -r docker rm -f -v || s=1; \
	docker network ls -q --filter label=supapace.test=1 | xargs -r docker network rm || s=1; \
	{ pkill -x -f "$(NODE_BIN)/sp-probe listen .*"; [ $$? -le 1 ]; } || s=1; \
	{ ! ip link show sp-nb0 >/dev/null 2>&1 || ip link del sp-nb0; } || s=1; \
	rm -f /run/supapace/drift-hold /run/sp-hold || s=1; \
	ip -o addr show to 198.51.100.7/32 | while read -r _ d _; do ip addr del 198.51.100.7/32 dev "$$d" || exit 1; done || s=1; \
	exit $$s

# Bracketed run on the node: reset, test binary $(3) (default reach.test) with $(1)
# as extra flags and $(2) as extra docker exec options (environment), reset. A
# failed reset fails the target, also after a passing run.
node_reach = docker exec $(NODE) sh -c '$(call reset,$(NODE_BIN)/supapaced)' || exit 1; \
	docker exec $(2) $(NODE) $(NODE_BIN)/$(or $(3),reach.test) $(REACH_FLAGS) $(1); s=$$?; \
	docker exec $(NODE) sh -c '$(call reset,$(NODE_BIN)/supapaced)' || exit 1; exit $$s

# $(call load_tar,ARCHIVE): loads ARCHIVE into $(NODE) unless the node has the image it
# names (its index.json, as node-init.sh reads it).
load_tar = ref=$$(tar -xOf "$(1)" index.json | sed -n 's/.*"io.containerd.image.name":"\([^"]*\)".*/\1/p'); \
	[ -n "$$ref" ] || { echo "$(1) names no image; run make images" >&2; exit 1; }; \
	docker exec $(NODE) docker image inspect "$$ref" >/dev/null 2>&1 || docker exec -i $(NODE) docker load -q < "$(1)"
# The browser harness's archive, required.
load_browsers = { test -f "$(BROWSERS_TAR)" || { echo "$(BROWSERS_TAR) is missing: run make browsers" >&2; exit 1; }; }; \
	$(call load_tar,$(BROWSERS_TAR))

.PHONY: setup build images unit gate-test node-up node-bare node-down reach reach-reboot reach-host measure public-check \
	standin-test harness-test lab studio browsers reach-dash node-proof browser-test

setup:
	git config core.hooksPath .githooks

build:
	@mkdir -p $(BIN)
	@if ls cmd/*/*.go >/dev/null 2>&1; then CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -o $(BIN)/ ./cmd/...; fi
	@# The wire proxy's two test builds; neither is in an image.
	@for tag in nopeer faulthook; do CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -tags $$tag -o $(BIN)/pgcap-$$tag ./cmd/pgcap || exit 1; done
	@if [ -d test/reach ]; then CGO_ENABLED=0 $(GO) test -c -tags reach -o $(BIN)/reach.test ./test/reach; fi

# PULL_ONLY=1 pulls the pinned images without saving archives (a host install, where this
# machine's Docker is the node's): the gateway and worker images are then left in this Docker only,
# and the stand-in is not pulled (a host install has none).
images: build
	@mkdir -p "$(IMAGE_CACHE)/src"
	scripts/cache-images.sh $(if $(PULL_ONLY),--pull-only) "$(IMAGE_CACHE)"
	@if [ -f deploy/gateway/Dockerfile ]; then \
		docker build -t $(GATEWAY_IMAGE) -f deploy/gateway/Dockerfile . \
		$(if $(PULL_ONLY),,&& scripts/cache-images.sh --save $(GATEWAY_IMAGE) supapace-gateway:local "$(IMAGE_CACHE)/supapace-gateway.tar"); \
	else echo "images: deploy/gateway/Dockerfile absent, gateway image skipped"; fi
	@# The source archive is kept only once its checksum matches images.lock; the
	@# build checks it again before unpacking it.
	@src="$(IMAGE_CACHE)/src/$(WORKER_SRC)" sum=$(patsubst sha256:%,%,$(WORKER_SRC_SHA256)); \
	echo "$$sum  $$src" | sha256sum -c --status 2>/dev/null && exit 0; \
	curl -fsSL -o "$$src.tmp" $(WORKER_SRC_URL) && echo "$$sum  $$src.tmp" | sha256sum -c --quiet && \
		mv "$$src.tmp" "$$src" || { rm -f "$$src.tmp"; echo "images: $(WORKER_SRC_URL) does not match images.lock" >&2; exit 1; }
	docker build -t $(WORKER_IMAGE) --build-arg WORKER_BASE=$(WORKER_BASE) --build-arg WORKER_SRC=$(WORKER_SRC) \
		--build-arg WORKER_SRC_SHA256=$(WORKER_SRC_SHA256) -f deploy/worker/Dockerfile "$(IMAGE_CACHE)/src"
	$(if $(PULL_ONLY),,scripts/cache-images.sh --save $(WORKER_IMAGE) supapace-worker:local "$(IMAGE_CACHE)/supapace-worker.tar")
	$(if $(PULL_ONLY),,docker image inspect $(S3_IMAGE) >/dev/null 2>&1 || docker pull -q $(S3_IMAGE))
	@# DASH=1: the wire proxy's image, and the Studio archive make studio writes.
	$(if $(DASH),@test -f "$(IMAGE_CACHE)/dash/supapace-studio.tar" || \
		{ echo "images: $(IMAGE_CACHE)/dash/supapace-studio.tar is missing: run make studio first" >&2; exit 1; })
	$(if $(DASH),docker build -t $(PGCAP_IMAGE) -f deploy/pgcap/Dockerfile .)
	$(if $(DASH),$(if $(PULL_ONLY),,scripts/cache-images.sh --save $(PGCAP_IMAGE) supapace-pgcap:local "$(IMAGE_CACHE)/dash/supapace-pgcap.tar"))

# The Studio image, its archive and its build record, into $(IMAGE_CACHE)/dash
# (studio/build.sh image: many minutes, and 10 GiB available). Never part of
# make images.
studio:
	@mkdir -p "$(IMAGE_CACHE)/dash"
	IMAGE_CACHE="$(IMAGE_CACHE)/dash" studio/build.sh image

# The browser harness's image and its archive. Its build fetches packages, so it
# runs where make images runs, never inside a node.
browsers:
	@mkdir -p "$(IMAGE_CACHE)/browsers"
	docker build -t $(BROWSERS_IMAGE) -f test/harness/browsers/Dockerfile test/harness/browsers
	scripts/cache-images.sh --save $(BROWSERS_IMAGE) supapace-browsers:local "$(BROWSERS_TAR)"

# The object-store client's tests against the stand-in image (pulled by make images);
# each such test is named TestStandin_*.
standin-test:
	SUPAPACE_STANDIN_TEST=1 $(GO) test -count=1 -run '^TestStandin_' ./internal/s3x/

unit: gate-test
	$(GO) vet ./... && $(GO) test -race ./...

# End-to-end cases of the public-content gate and its hooks, in throw-away repositories.
gate-test:
	scripts/test-check-public.sh

node-up: MODE := full
node-bare: MODE := bare
# Unless SP_OFFSITE=0, the object-store stand-in $(NODE)-s3 runs beside the node on two
# lab networks (test/harness/s3/setup.sh) and the node resolves its name.
node-up node-bare:
	@avail=$$(awk '/^MemAvailable:/ {print int($$2 / 1048576)}' /proc/meminfo); \
		[ "$$avail" -ge $$(($(NODE_MEM) + 2)) ] || { echo "node: $$avail GiB available; a node of $(NODE_MEM) GiB needs $$(($(NODE_MEM) + 2))" >&2; exit 1; }
	docker build --build-arg NODE_IMAGE=$(NODE_BASE) -t $(NODE_IMAGE) test/harness/node
	mkdir -p $(BIN) "$(IMAGE_CACHE)"
	docker run -d --privileged --cgroupns private --memory $(NODE_MEM)g --stop-timeout 60 --name $(NODE) -e SP_NODE_MODE=$(MODE)$(if $(DASH), -e SP_STUDIO_DOMAIN=$(STUDIO_DOMAIN)) \
		$(if $(filter 0,$(SP_OFFSITE)),,--add-host $(S3_NAME):$(S3_ADDR1)) \
		-v $(NODE)-docker:/var/lib/docker -v $(NODE)-state:/var/lib/sp \
		-v "$(CURDIR)/$(BIN)":$(NODE_BIN):ro -v "$(IMAGE_CACHE)":/images:ro $(NODE_IMAGE)
	@for i in $$(seq 300); do \
		docker exec $(NODE) sh -c 'test -e /run/sp-node-ready && docker info' >/dev/null 2>&1 && exit 0; \
		if [ "$$(docker inspect -f '{{.State.Running}}' $(NODE))" != true ]; then \
			echo "node: $(NODE) stopped during boot:" >&2; docker logs --tail 20 $(NODE) >&2; exit 1; fi; \
		sleep 1; done; \
		echo "node: docker did not come up" >&2; exit 1
	@# Full mode: also wait until the daemon answers on its admin socket.
	@if [ $(MODE) = full ] && [ -x $(BIN)/supapaced ]; then \
		for i in $$(seq 60); do \
			docker exec $(NODE) $(NODE_BIN)/supapace node check 2>/dev/null | grep -q '"checks"' && exit 0; sleep 1; done; \
		echo "node: the daemon did not answer node check within 60 s:" >&2; \
		docker exec $(NODE) tail -n 20 /var/log/supapaced.log >&2; exit 1; fi
	$(if $(filter 0,$(SP_OFFSITE)),,NODE=$(NODE) NODE_IMAGE=$(NODE_IMAGE) S3_IMAGE=$(S3_IMAGE) $(S3_LAB) test/harness/s3/setup.sh)

# Volumes go too: a kept Docker volume would leave stale proj-* networks behind. The
# stand-in's lab first: the node leaves both networks, then the stand-in and the networks go.
node-down:
	-@for n in $(NODE)-net $(NODE)-net2; do docker network disconnect -f $$n $(NODE) >/dev/null 2>&1; done; \
		docker rm -f -v $(NODE)-s3 >/dev/null 2>&1; docker network rm $(NODE)-net $(NODE)-net2 >/dev/null 2>&1; true
	-docker rm -f $(NODE)
	-docker volume rm $(NODE)-docker $(NODE)-state

# With the node's stand-in present the suite is told so (SUPAPACE_STANDIN=1): a test
# that needs it then fails instead of skipping.
reach: build
	$(call node_reach,$(REACH_ARGS),$$(docker container inspect $(NODE)-s3 >/dev/null 2>&1 && echo --env SUPAPACE_STANDIN=1))

# The suite built with the tags reach and dash (dash.test: every test of reach.test
# and the dashboard's), on a node started with DASH=1, bracketed as make reach is.
# The browser harness's image is loaded into the node first when its archive exists.
reach-dash: build
	CGO_ENABLED=0 $(GO) test -c -tags 'reach dash' -o $(BIN)/dash.test ./test/reach
	@if [ -f "$(BROWSERS_TAR)" ]; then $(load_browsers); fi
	$(call node_reach,$(REACH_ARGS),$$(docker container inspect $(NODE)-s3 >/dev/null 2>&1 && echo --env SUPAPACE_STANDIN=1),dash.test)

# A package's node tests (TestNode_…, or RUN=<pattern>), built with the reach tag, in a
# node started bare, with the archives of $(IMAGE_CACHE)/dash loaded into it.
node-proof: build
	@[ -n "$(PKG)" ] || { echo "usage: make node-proof PKG=<directory> [RUN=<pattern>]" >&2; exit 2; }
	CGO_ENABLED=0 $(GO) test -c -tags reach -o $(BIN)/proof.test ./$(PKG)
	@# The archives a dashboard node loads, so that a proof of the proxy has its image;
	@# a Studio variant (supapace-studio-NAME.tar) is never loaded by itself.
	@for f in "$(IMAGE_CACHE)"/dash/*.tar; do case $$f in */supapace-studio-*.tar) continue ;; esac; \
		[ ! -e "$$f" ] || { $(call load_tar,$$f); } || exit 1; done
	docker exec $(NODE) $(NODE_BIN)/proof.test -test.v -test.timeout 60m -test.run '$(or $(RUN),^TestNode_)'

# The browser harness's own tests (test/browser), in a node started bare, with the
# harness's image loaded into it (make browsers).
browser-test: build
	CGO_ENABLED=0 $(GO) test -c -tags browser -o $(BIN)/browser.test ./test/browser
	@$(load_browsers)
	docker exec $(NODE) $(NODE_BIN)/browser.test -test.v -test.timeout 60m $(if $(RUN),-test.run '$(RUN)')

reach-reboot: build
	docker restart -t 60 $(NODE)
	@for i in $$(seq 180); do docker exec $(NODE) test -S /run/supapace/admin.sock && exit 0; sleep 1; done; \
		echo "node: admin socket did not appear" >&2; exit 1
	$(call node_reach,-test.run 'TestReach05_AfterReboot|TestReach03' $(REACH_ARGS),-e SUPAPACE_REBOOT=1)

# On a host prepared by scripts/install-node.sh, as root. The suite runs the
# binaries from $(NODE_BIN), as in the test node, so they are installed there first.
reach-host: build
	install -d -m 0755 $(NODE_BIN) && install -m 0755 $(BIN)/* $(NODE_BIN)/ || exit 1; \
	sh -c '$(call reset,supapaced)' || exit 1; \
	SUPAPACE_HOST=1 $(BIN)/reach.test $(REACH_FLAGS) $(REACH_ARGS); s=$$?; \
	sh -c '$(call reset,supapaced)' || exit 1; exit $$s

# Ctrl-C ends docker exec (with status 0) but reaches no process inside the node: a
# script still running afterwards (its pid file exists) is stopped.
measure:
	docker exec -i $(foreach v,REF IDLE LOAD CLIENTS,$(if $($(v)),-e $(v)=$($(v)))) $(NODE) sh -s < test/measure/cluster_mem.sh; s=$$?; \
	docker exec $(NODE) sh -c 'test ! -e /run/sp-measure.pid || kill $$(cat /run/sp-measure.pid)'; exit $$s

public-check:
	scripts/check-public.sh --tree

# Checks of the harness itself against the running node $(NODE) (test/harness/harness-test.sh).
harness-test: build
	NODE=$(NODE) NODE_IMAGE=$(NODE_IMAGE) IMAGE_CACHE="$(IMAGE_CACHE)" BIN=$(BIN) LOCK=$(LOCK) test/harness/harness-test.sh

# The lab slot and the addresses derived from it, one KEY=value per line (for the harness).
lab:
	@printf '%s\n' $(S3_LAB)
