DOCKER := docker
SVC_HANDLER_ADDR ?= 0x0

.PHONY: build

help: ## Show this help
	@egrep -h '\s##\s' $(MAKEFILE_LIST) | sort | \
	awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: compose.yaml ## Build the Docker container(s)
	$(DOCKER) compose build
	$(DOCKER) compose run --rm investee /build-entrypoint.sh

# execute build before once
run-machine: ## Run the Docker container and QEMU and investee
	$(DOCKER) compose run --name investee -v $(XAUTHORITY):/root/.Xauthority:ro -e DISPLAY=$(DISPLAY) --rm investee /investee-entrypoint.sh

# execute run-machine before
# Run 'cat /proc/kallsyms | grep el0t_64_sync_handler' in NW terminal to get SVC_HANDLER_ADDR
run-svc-log: ## Attach to a running container and log SVCs via breakpoint
	$(DOCKER) exec -it investee /svc-log-entrypoint.sh $(SVC_HANDLER_ADDR)

run-sh: ## Run the Docker container and spawn a shell
	$(DOCKER) compose run -v $(XAUTHORITY):/root/.Xauthority:ro -e DISPLAY=$(DISPLAY) --rm investee /sh-entrypoint.sh
