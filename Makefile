#!/usr/bin/env make

SHELL="/bin/bash"
NAME="minitrue"
TAG="procamora:$(NAME)"

.PHONY: help all build run shell ssh


all: build run


build: ## Build a dockerimage
	#@docker build --no-cache --tag "$(TAG)" -f ./Dockerfile .
	@docker build --tag "$(TAG)" -f ./Dockerfile .

run:
#	@mkdir -p ./data
	@docker run -ti --rm --network=host --env-file=.env --hostname="$(NAME)" -p 2222:22 --name "$(NAME)" -v $(pwd)/data:/root/ "$(TAG)"

help: ## Print this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

shell: ## shell inside docker container
	@docker exec -ti  "$(NAME)" /bin/zsh

ssh: ## shell inside docker container with SSH
	@ssh -i ~/.ssh/bbva -p 2222 root@127.0.0.1

