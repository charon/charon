#!/bin/sh

set -e

# Run locally with:
#docker run --privileged --rm \
#  -v "$(pwd):/workspace" \
#  --name dind \
#  -w /workspace \
#  docker:23-dind \
#  sh -c " \
#    dockerd-entrypoint.sh > /tmp/dockerd.log 2>&1 & \
#    sleep 2 && \
#    DOCKER_HOST=unix:///var/run/docker.sock ./test-e2e.sh \
#  "

echo "=== E2E Test Script ==="

cleanup_charon_container=0
cleanup_charon_image=0
cleanup_playwright_image=0
cleanup_network=0
cleanup_certs=0

cleanup() {
  set +e

  if [ "$cleanup_charon_container" -ne 0 ]; then
    echo "Logs charon"
    docker logs charon-container

    echo "Stopping charon Docker container"
    docker stop charon-container
  fi

  if [ "$cleanup_charon_image" -ne 0 ]; then
    echo "Removing charon Docker image"
    docker image rm -f charon-image
  fi

  if [ "$cleanup_playwright_image" -ne 0 ]; then
    echo "Removing playwright Docker image"
    docker image rm -f charon-playwright-image
  fi

  if [ "$cleanup_network" -ne 0 ]; then
    echo "Removing Docker network"
    docker network rm charon-e2e-network
  fi

  if [ "$cleanup_certs" -ne 0 ]; then
    echo "Cleaning up temporary files"
    rm test-e2e-rootCA.pem
  fi
}

trap cleanup EXIT

# Create Docker network for E2E tests.
echo "Creating Docker network..."
docker network create charon-e2e-network
cleanup_network=1

echo "1. Installing dependencies and generating certificates..."

# Install required tools for certificate generation.
apk --update add openssl curl

# Install Go tools for certificate generation.
curl -L https://github.com/FiloSottile/mkcert/releases/download/v1.4.4/mkcert-v1.4.4-linux-amd64 -o /usr/local/bin/mkcert && chmod +x /usr/local/bin/mkcert
curl -L https://github.com/jphastings/jwker/releases/download/v0.2.1/jwker_Linux_x86_64.tar.gz | tar -xz -C /usr/local/bin jwker
mkcert -install

# Generate certificates
mkcert charon-container 127.0.0.1 ::1
echo "chs-$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > .hmac.secret
openssl genpkey -algorithm RSA -out rsa-key.pem -pkeyopt rsa_keygen_bits:2048
jwker rsa-key.pem .rsa-key.jwk
rm rsa-key.pem
chmod 644 .rsa-key.jwk charon-container+2.pem charon-container+2-key.pem .hmac.secret

# Copy mkcert CA certificate for Docker build.
cp "$(mkcert -CAROOT)/rootCA.pem" test-e2e-rootCA.pem
cleanup_certs=1

echo "2. Building Docker images..."

# Build the Charon Docker image from Dockerfile.
docker build --target production -t charon-image .
cleanup_charon_image=1

# Build the Playwright test image.
docker build -f playwright.dockerfile -t charon-playwright-image .
cleanup_playwright_image=1

echo "3. Starting Charon container..."

# Start Charon container with certificates.
docker run --rm -d \
  --name charon-container \
  --network charon-e2e-network \
  -v "$(pwd):/data" \
  charon-image \
  -k /data/charon-container+2.pem \
  -K /data/charon-container+2-key.pem \
  --secret=/data/.hmac.secret \
  --oidc.keys.rsa=/data/.rsa-key.jwk
cleanup_charon_container=1

echo "4. Waiting for Charon service to be ready..."

sleep 5

echo "5. Running Playwright tests..."

# Set environment variables for Playwright.
export LINK_PUBLISH_JOB_ID="${CI_JOB_ID}"

# Run Playwright tests in separate container.
docker run --rm \
  --name charon-playwright \
  --network charon-e2e-network \
  -v "$(pwd)/playwright-report:/app/playwright-report" \
  -v "$(pwd)/test-results:/app/test-results" \
  -e CHARON_URL="https://charon-container:8080" \
  -e LINK_PUBLISH_JOB_ID \
  charon-playwright-image

echo "=== E2E Tests Completed Successfully ==="
