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

.PHONY: build build-static test test-ci lint lint-ci fmt fmt-ci upgrade clean release lint-docs lint-docs-ci audit watch

# dist is build only if it is missing. Use "make clean" to remove it to build it again.
build: dist
	go build -trimpath -ldflags "-s -w -X gitlab.com/tozd/go/cli.Version=${VERSION} -X gitlab.com/tozd/go/cli.BuildTimestamp=${BUILD_TIMESTAMP} -X gitlab.com/tozd/go/cli.Revision=${REVISION}" -o charon gitlab.com/charon/charon/cmd/charon

# dist is build only if it is missing. Use "make clean" to remove it to build it again.
build-static: dist
	go build -trimpath -ldflags "-s -w -linkmode external -extldflags '-static' -X gitlab.com/tozd/go/cli.Version=${VERSION} -X gitlab.com/tozd/go/cli.BuildTimestamp=${BUILD_TIMESTAMP} -X gitlab.com/tozd/go/cli.Revision=${REVISION}" -o charon gitlab.com/charon/charon/cmd/charon

dist: node_modules src vite.config.ts tsconfig.json tsconfig.node.json tailwind.config.js LICENSE
	npm run build

node_modules:
	npm install

dist/index.html:
	mkdir -p dist
	if [ ! -e dist/index.html ]; then echo "<html><body>dummy content</body></html>" > dist/index.html; fi

test: dist/index.html
	gotestsum --format pkgname --packages ./... -- -race -timeout 10m -cover -covermode atomic

test-ci: dist/index.html
	gotestsum --format pkgname --packages ./... --junitfile tests.xml -- -race -timeout 10m -coverprofile=coverage.txt -covermode atomic
	gocover-cobertura < coverage.txt > coverage.xml
	go tool cover -html=coverage.txt -o coverage.html

lint: dist/index.html
	golangci-lint run --timeout 4m --color always --allow-parallel-runners --fix --max-issues-per-linter 0 --max-same-issues 0

lint-ci: dist/index.html
	golangci-lint run --timeout 4m --max-issues-per-linter 0 --max-same-issues 0 --out-format colored-line-number,code-climate:codeclimate.json

fmt:
	go mod tidy
	git ls-files --cached --modified --other --exclude-standard -z | grep -z -Z '.go$$' | xargs -0 gofumpt -w
	git ls-files --cached --modified --other --exclude-standard -z | grep -z -Z '.go$$' | xargs -0 goimports -w -local gitlab.com/charon/charon

fmt-ci: fmt
	git diff --exit-code --color=always

upgrade:
	go run github.com/icholy/gomajor@v0.13.2 get all
	go mod tidy

clean:
	rm -rf coverage.* codeclimate.json tests.xml coverage dist charon

release:
	npx --yes --package 'release-it@15.4.2' --package '@release-it/keep-a-changelog@3.1.0' -- release-it

lint-docs:
	npx --yes --package 'markdownlint-cli@~0.41.0' -- markdownlint --ignore-path .gitignore --ignore testdata/ --fix '**/*.md'

lint-docs-ci: lint-docs
	git diff --exit-code --color=always

audit: dist/index.html
	go list -json -deps ./... | nancy sleuth --skip-update-check

watch:
	CompileDaemon -build="make --silent build" -command="./charon -D -k localhost+2.pem -K localhost+2-key.pem" -include="*.json" -include="go.mod" -include="go.sum" -exclude-dir=.git -graceful-kill=true -log-prefix=false -color=true
