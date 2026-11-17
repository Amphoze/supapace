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
IMAGE_CACHE ?= $(HOME)/.cache/supapace/images
LOCK := internal/nodecfg/images.lock
# The harness base image, name@digest from images.lock; passed to the node
# Dockerfile as the build argument NODE_IMAGE (ARG before FROM).
NODE_BASE = $(shell sed -n 's/^ *"node": *{"tag": *"\([^":]*\)[^"]*", *"digest": *"\([^"]*\)".*/\1@\2/p' $(LOCK))
REACH_FLAGS := -test.v -test.parallel 1
REACH_ARGS ?=

# Suite reset, run on the node before and after every reach run whatever its exit
# status: drop the drift hold and any failpoint, reload our tables, remove every scratch object
# labelled supapace.test=1 and the second source address of test 17. A failed rules
# load stops at once; any other failed step fails the reset after the rest has run.
# $(1) is the supapaced binary.
reset = s=0; rm -f /run/supapace/drift-hold /run/supapace/failpoint || s=1; $(1) nft load || exit 1; \
	docker ps -aq --filter label=supapace.test=1 | xargs -r docker rm -f || s=1; \
	docker network ls -q --filter label=supapace.test=1 | xargs -r docker network rm || s=1; \
	ip -o addr show to 198.51.100.7/32 | while read -r _ d _; do ip addr del 198.51.100.7/32 dev "$$d" || exit 1; done || s=1; \
	exit $$s

# Bracketed run on the node: reset, test binary with $(1) as extra flags, reset.
# A failed reset fails the target, also after a passing run.
node_reach = docker exec $(NODE) sh -c '$(call reset,$(NODE_BIN)/supapaced)' || exit 1; \
	docker exec $(NODE) $(NODE_BIN)/reach.test $(REACH_FLAGS) $(1); s=$$?; \
	docker exec $(NODE) sh -c '$(call reset,$(NODE_BIN)/supapaced)' || exit 1; exit $$s

.PHONY: setup build images unit gate-test node-up node-bare node-down reach reach-reboot reach-host measure public-check

setup:
	git config core.hooksPath .githooks

build:
	@mkdir -p $(BIN)
	@if ls cmd/*/*.go >/dev/null 2>&1; then CGO_ENABLED=0 $(GO) build -buildvcs=false -trimpath -o $(BIN)/ ./cmd/...; fi
	@if [ -d test/reach ]; then CGO_ENABLED=0 $(GO) test -c -tags reach -o $(BIN)/reach.test ./test/reach; fi

images: build
	scripts/cache-images.sh "$(IMAGE_CACHE)"
	@if [ -f deploy/gateway/Dockerfile ]; then \
		docker build -t $(GATEWAY_IMAGE) -f deploy/gateway/Dockerfile . && \
		docker save -o "$(IMAGE_CACHE)/supapace-gateway.tar" $(GATEWAY_IMAGE); \
	else echo "images: deploy/gateway/Dockerfile absent, gateway image skipped"; fi

unit: gate-test
	$(GO) vet ./... && $(GO) test -race ./...

# End-to-end cases of the public-content gate and its hooks, in throw-away repositories.
gate-test:
	scripts/test-check-public.sh

node-up: MODE := full
node-bare: MODE := bare
node-up node-bare:
	docker build --build-arg NODE_IMAGE=$(NODE_BASE) -t $(NODE_IMAGE) test/harness/node
	mkdir -p $(BIN) "$(IMAGE_CACHE)"
	docker run -d --privileged --cgroupns private --memory 4g --stop-timeout 60 --name $(NODE) -e SP_NODE_MODE=$(MODE) \
		-v $(NODE)-docker:/var/lib/docker -v $(NODE)-state:/var/lib/sp \
		-v "$(CURDIR)/$(BIN)":$(NODE_BIN):ro -v "$(IMAGE_CACHE)":/images:ro $(NODE_IMAGE)
	@for i in $$(seq 300); do \
		docker exec $(NODE) sh -c 'test -e /run/sp-node-ready && docker info' >/dev/null 2>&1 && exit 0; \
		if [ "$$(docker inspect -f '{{.State.Running}}' $(NODE))" != true ]; then \
			echo "node: $(NODE) stopped during boot:" >&2; docker logs --tail 20 $(NODE) >&2; exit 1; fi; \
		sleep 1; done; \
		echo "node: docker did not come up" >&2; exit 1

# Volumes go too: a kept Docker volume would leave stale proj-* networks behind.
node-down:
	-docker rm -f $(NODE)
	-docker volume rm $(NODE)-docker $(NODE)-state

reach: build
	$(call node_reach,$(REACH_ARGS))

reach-reboot: build
	docker restart -t 60 $(NODE)
	@for i in $$(seq 180); do docker exec $(NODE) test -S /run/supapace/admin.sock && exit 0; sleep 1; done; \
		echo "node: admin socket did not appear" >&2; exit 1
	$(call node_reach,-test.run 'TestReach05_AfterReboot|TestReach03' $(REACH_ARGS))

# On a host prepared by scripts/install-node.sh, as root.
reach-host: build
	sh -c '$(call reset,supapaced)' || exit 1; \
	SUPAPACE_HOST=1 $(BIN)/reach.test $(REACH_FLAGS) $(REACH_ARGS); s=$$?; \
	sh -c '$(call reset,supapaced)' || exit 1; exit $$s

measure:
	docker exec -i $(NODE) sh -s < test/measure/cluster_mem.sh

public-check:
	scripts/check-public.sh --tree
