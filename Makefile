SHELL = /usr/bin/env bash -o pipefail

# We use ifeq instead of ?= so that we set variables
# also when they are defined, but empty.
ifeq ($(VERSION),)
 VERSION = `git describe --tags --always --dirty=+`
endif
ifeq ($(BUILD_TIMESTAMP),)
 BUILD_TIMESTAMP = `date -u +%FT%TZ`
endif
ifeq ($(REVISION),)
 REVISION = `git rev-parse HEAD`
endif

.PHONY: build build-static test test-ci lint lint-ci fmt fmt-ci clean release lint-docs audit serve watch

# dist is build only if it is missing. Use "make clean" to remove it to build it again.
build: dist
	go build -trimpath -ldflags "-s -w -X gitlab.com/tozd/go/cli.Version=${VERSION} -X gitlab.com/tozd/go/cli.BuildTimestamp=${BUILD_TIMESTAMP} -X gitlab.com/tozd/go/cli.Revision=${REVISION}" -o charon gitlab.com/charon/charon/cmd/charon

# dist is build only if it is missing. Use "make clean" to remove it to build it again.
build-static: dist
	go build -trimpath -ldflags "-s -w -linkmode external -extldflags '-static' -X gitlab.com/tozd/go/cli.Version=${VERSION} -X gitlab.com/tozd/go/cli.BuildTimestamp=${BUILD_TIMESTAMP} -X gitlab.com/tozd/go/cli.Revision=${REVISION}" -o charon gitlab.com/charon/charon/cmd/charon

dist: node_modules vite.config.ts tsconfig.json tsconfig.node.json tailwind.config.js
	npm run build

node_modules:
	npm install

dist/index.html:
	mkdir -p dist
	if [ ! -e dist/index.html ]; then echo "dummy contents" > dist/index.html; fi

test: dist/index.html
	gotestsum --format pkgname --packages ./... -- -race -timeout 10m -cover -covermode atomic

test-ci: dist/index.html
	gotestsum --format pkgname --packages ./... --junitfile tests.xml -- -race -timeout 10m -coverprofile=coverage.txt -covermode atomic
	gocover-cobertura < coverage.txt > coverage.xml
	go tool cover -html=coverage.txt -o coverage.html

lint: dist/index.html
	golangci-lint run --timeout 4m --color always --allow-parallel-runners --fix

lint-ci: dist/index.html
	golangci-lint run --timeout 4m --out-format colored-line-number,code-climate:codeclimate.json

fmt:
	go mod tidy
	git ls-files --cached --modified --other --exclude-standard -z | grep -z -Z '.go$$' | xargs -0 gofumpt -w
	git ls-files --cached --modified --other --exclude-standard -z | grep -z -Z '.go$$' | xargs -0 goimports -w -local gitlab.com/charon/charon

fmt-ci: fmt
	git diff --exit-code --color=always

clean:
	rm -rf coverage.* codeclimate.json tests.xml coverage dist charon

release:
	npx --yes --package 'release-it@15.4.2' --package '@release-it/keep-a-changelog@3.1.0' -- release-it

lint-docs:
	npx --yes --package 'markdownlint-cli@~0.34.0' -- markdownlint --ignore-path .gitignore --ignore testdata/ '**/*.md'

audit: dist/index.html
	go list -json -deps ./... | nancy sleuth --skip-update-check

watch:
	CompileDaemon -build="make --silent build" -command="./charon -d -O -k localhost+2.pem -K localhost+2-key.pem" -include="*.json" -include="go.mod" -include="go.sum" -exclude-dir=.git -graceful-kill=true -log-prefix=false -color=true
