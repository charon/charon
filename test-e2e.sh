#!/bin/bash

set -e
set -o pipefail

# Run locally with:
#docker run --privileged --rm \
#  -v "$(pwd):/workspace" \
#  --name dind \
#  -w /workspace \
#  docker:28-dind \
#  sh -c " \
#    dockerd-entrypoint.sh > /tmp/dockerd.log 2>&1 & \
#    sleep 2 && \
#    DOCKER_HOST=unix:///var/run/docker.sock ./test-e2e.sh \
#  "

echo "=== E2E Test Script ==="

ROOT_CA_FILE="test-e2e-rootCA.pem"
CHARON_CONTAINER="charon-container"
CHARON_SIPASS_CONTAINER="charon-sipass-container"
SIPASS_TUNNEL_CONTAINER="sipass-tunnel"
CHARON_IMAGE="charon-image"
PLAYWRIGHT_IMAGE="charon-playwright-image"
NETWORK="charon-e2e-network"

cleanup_charon_container=0
cleanup_charon_sipass_container=0
cleanup_mailpit_container=0
cleanup_charon_image=0
cleanup_playwright_image=0
cleanup_network=0
cleanup_certs=0
cleanup_ssh_tunnel=0

cleanup() {
  set +e

  if [ "$cleanup_charon_container" -ne 0 ]; then
    echo "Logs charon"
    docker logs "$CHARON_CONTAINER"

    echo "Stopping charon Docker container (if still running)"
    docker stop "$CHARON_CONTAINER"
    docker rm -f "$CHARON_CONTAINER"
  fi

  if [ "$cleanup_charon_sipass_container" -ne 0 ]; then
    echo "Logs charon SIPASS"
    docker logs "$CHARON_SIPASS_CONTAINER"

    echo "Stopping charon SIPASS Docker container (if still running)"
    docker stop "$CHARON_SIPASS_CONTAINER"
    docker rm -f "$CHARON_SIPASS_CONTAINER"
  fi

  if [ "$cleanup_mailpit_container" -ne 0 ]; then
    echo "Logs mailpit"
    docker logs mailpit

    echo "Stopping mailpit Docker container (if still running)"
    docker stop mailpit
    docker rm -f mailpit
  fi

  if [ "$cleanup_charon_image" -ne 0 ]; then
    echo "Removing charon Docker image"
    docker image rm -f "$CHARON_IMAGE"
  fi

  if [ "$cleanup_playwright_image" -ne 0 ]; then
    echo "Removing playwright Docker image"
    docker image rm -f "$PLAYWRIGHT_IMAGE"
  fi

  if [ "$cleanup_certs" -ne 0 ]; then
    echo "Cleaning up temporary files"
    rm "$ROOT_CA_FILE"
  fi

  if [ "$cleanup_ssh_tunnel" -ne 0 ]; then
    echo "Stopping SSH tunnel container"
    docker logs "$SIPASS_TUNNEL_CONTAINER"
    docker stop "$SIPASS_TUNNEL_CONTAINER"
    docker rm -f "$SIPASS_TUNNEL_CONTAINER"
  fi

  if [ "$cleanup_network" -ne 0 ]; then
    echo "Removing Docker network"
    docker network rm "$NETWORK"
  fi
}

trap cleanup EXIT

# Create Docker network for E2E tests.
echo "Creating Docker network..."
docker network create "$NETWORK"
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
mkcert mailpit 127.0.0.1 ::1
mkcert sipasstest.peer.id 127.0.0.1 ::1
echo "chs-$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=')" > .hmac.secret
openssl genpkey -algorithm RSA -out rsa-key.pem -pkeyopt rsa_keygen_bits:2048
jwker rsa-key.pem .rsa-key.jwk
rm rsa-key.pem
chmod 644 .rsa-key.jwk charon-container+2.pem charon-container+2-key.pem .hmac.secret
chmod 644 mailpit+2.pem mailpit+2-key.pem
chmod 644 sipasstest.peer.id+2.pem sipasstest.peer.id+2-key.pem

# Copy mkcert CA certificate for Docker build.
cp "$(mkcert -CAROOT)/rootCA.pem" "$ROOT_CA_FILE"
cleanup_certs=1

echo "2. Building Docker images..."

# Build the Charon Docker image from Dockerfile.
docker build --target production --build-arg CHARON_BUILD_FLAGS="-cover -race -covermode atomic" --build-arg VITE_COVERAGE=true --build-arg VITE_E2E_TESTS=true -t "$CHARON_IMAGE" .
cleanup_charon_image=1

# Build the Playwright test image.
docker build -f playwright.dockerfile -t "$PLAYWRIGHT_IMAGE" .
cleanup_playwright_image=1

echo "3. Starting Mailpit container..."

# Start mailpit for e-mail auth testing.
docker run -d \
    --name mailpit \
    --network "$NETWORK" \
    -v "$(pwd)/mailpit+2.pem:/certs/mailpit+2.pem" \
    -v "$(pwd)/mailpit+2-key.pem:/certs/mailpit+2-key.pem" \
    axllent/mailpit:v1.27 \
    --smtp-tls-cert /certs/mailpit+2.pem \
    --smtp-tls-key /certs/mailpit+2-key.pem
cleanup_mailpit_container=1

echo "4. Starting Charon container..."

mkdir -p coverage
# We chown to the user Charon runs inside the Docker container so that it can write coverage.
chown 1000:1000 coverage

# Start Charon container with certificates.
docker run -d \
  --name "$CHARON_CONTAINER" \
  --network "$NETWORK" \
  -v "$(pwd):/data" \
  -e GOCOVERDIR=/data/coverage \
  -e SSL_CERT_FILE=/data/"$ROOT_CA_FILE" \
  -e SSL_CERT_DIR=/etc/ssl/certs \
  "$CHARON_IMAGE" \
  -k /data/charon-container+2.pem \
  -K /data/charon-container+2-key.pem \
  --secret=/data/.hmac.secret \
  --oidc.key=/data/.rsa-key.jwk \
  --mail.host=mailpit \
  --mail.port=1025 \
  --mail.auth=none \
  --mail.from=test@charon.local
cleanup_charon_container=1

echo "5. Waiting for Charon service to be ready..."

sleep 5

echo "6. Running Playwright tests..."

# Set environment variables for Playwright.
export LINK_PUBLISH_JOB_ID="${CI_JOB_ID}"

# Run Playwright tests in separate container.
docker run --rm \
  --name charon-playwright \
  --network "$NETWORK" \
  -v "$(pwd)/playwright-report:/src/charon/playwright-report" \
  -v "$(pwd)/blob-report:/src/charon/blob-report" \
  -v "$(pwd)/test-results:/src/charon/test-results" \
  -v "$(pwd)/playwright-screenshots:/src/charon/playwright-screenshots" \
  -v "$(pwd)/coverage-frontend:/src/charon/coverage-frontend" \
  -v "$(pwd)/a11y-report:/src/charon/a11y-report" \
  -v "$(pwd)/.nyc_output:/.nyc_output" \
  -e CHARON_URL="https://$CHARON_CONTAINER:8080" \
  -e MAILPIT_URL="http://mailpit:8025" \
  -e LINK_PUBLISH_JOB_ID \
  -e UPDATE_SCREENSHOTS \
  -e PLAYWRIGHT_TAG="main" \
  "$PLAYWRIGHT_IMAGE"

# Stop the Charon container and check its exit code.
echo "7. Stopping Charon container..."
docker stop "$CHARON_CONTAINER"
CHARON_EXIT_CODE=$(docker wait "$CHARON_CONTAINER")

if [ "$CHARON_EXIT_CODE" -ne 0 ]; then
  echo "ERROR: Charon container exited with code $CHARON_EXIT_CODE"
  exit 1
fi

# Conditionally run SIPASS tests.
missing_vars=""
[ -z "$SIPASS_KEY_PATH" ] && missing_vars="$missing_vars SIPASS_KEY_PATH"
[ -z "$SIPASS_SSH_KEY_PATH" ] && missing_vars="$missing_vars SIPASS_SSH_KEY_PATH"
[ -z "$SIPASS_KNOWN_HOSTS_PATH" ] && missing_vars="$missing_vars SIPASS_KNOWN_HOSTS_PATH"
[ -z "$SIPASS_TESTUSER_CERT_PATH" ] && missing_vars="$missing_vars SIPASS_TESTUSER_CERT_PATH"
[ -z "$SIPASS_TESTUSER_KEY_PATH" ] && missing_vars="$missing_vars SIPASS_TESTUSER_KEY_PATH"

if [ -n "$missing_vars" ]; then
  echo "SKIP: Missing required environment variables:$missing_vars"
  echo "SIPASS tests will be skipped"
  exit 0
fi

# SIPASS-specific configuration
DOMAIN="sipasstest.peer.id"

echo "8. Setting up SSH tunnel for SIPASS..."

# Start SSH tunnel container
docker run -d \
  --name "$SIPASS_TUNNEL_CONTAINER" \
  --network "$NETWORK" \
  -v "$SIPASS_KNOWN_HOSTS_PATH:/ssh/known_hosts" \
  -v "$SIPASS_SSH_KEY_PATH:/ssh/ssh_key_b64" \
  alpine:3.22 \
  sh -c "
    apk --update add dropbear-dbclient &&
    mkdir -p ~/.ssh &&
    cp /ssh/known_hosts ~/.ssh/known_hosts &&
    chmod 600 ~/.ssh/known_hosts &&
    base64 -d /ssh/ssh_key_b64 > /ssh/ssh_key &&
    chmod 600 /ssh/ssh_key &&
    dbclient -R 0.0.0.0:8080:$CHARON_SIPASS_CONTAINER:8080 -p 2200 -T -N -i /ssh/ssh_key nobody@de1.plast8.si
  "
cleanup_ssh_tunnel=1

echo "SSH tunnel container started"

sleep 2

echo "9. Starting Charon container for SIPASS..."

# Start Charon container with SIPASS configuration.
docker run -d \
  --name "$CHARON_SIPASS_CONTAINER" \
  --network "$NETWORK" \
  -v "$(pwd):/data" \
  -v "$SIPASS_KEY_PATH:/sipass-key.pem" \
  -e GOCOVERDIR=/data/coverage \
  -e SSL_CERT_FILE=/data/"$ROOT_CA_FILE" \
  -e SSL_CERT_DIR=/etc/ssl/certs \
  "$CHARON_IMAGE" \
  -k /data/"$DOMAIN"+2.pem \
  -K /data/"$DOMAIN"+2-key.pem \
  --secret=/data/.hmac.secret \
  --oidc.key=/data/.rsa-key.jwk \
  --external-port=443 \
  --domain="$DOMAIN" \
  --sipass.metadata-url=https://sicas-test.sigov.si/static/idp-metadata.xml \
  --sipass.entity-id=Plast8_PeerID \
  --sipass.key=/sipass-key.pem
cleanup_charon_sipass_container=1

echo "10. Waiting for Charon service to be ready..."

sleep 3

echo "11. Running Playwright SIPASS tests..."

# Run Playwright SIPASS tests.
docker run --rm \
  --name charon-playwright \
  --network "$NETWORK" \
  -v "$(pwd)/playwright-report:/src/charon/playwright-report" \
  -v "$(pwd)/blob-report:/src/charon/blob-report" \
  -v "$(pwd)/test-results-sipass:/src/charon/test-results" \
  -v "$(pwd)/playwright-screenshots:/src/charon/playwright-screenshots" \
  -v "$(pwd)/coverage-frontend:/src/charon/coverage-frontend" \
  -v "$(pwd)/a11y-report:/src/charon/a11y-report" \
  -v "$(pwd)/.nyc_output:/.nyc_output" \
  -v "$SIPASS_TESTUSER_CERT_PATH:/sipass-testuser.pem" \
  -v "$SIPASS_TESTUSER_KEY_PATH:/sipass-testuser.crt" \
  -e LINK_PUBLISH_JOB_ID \
  -e UPDATE_SCREENSHOTS \
  -e SIPASS_TESTUSER_CERT_PATH="/sipass-testuser.pem" \
  -e SIPASS_TESTUSER_KEY_PATH="/sipass-testuser.crt" \
  -e PLAYWRIGHT_TAG="SIPASS" \
  "$PLAYWRIGHT_IMAGE" \
  npx playwright test tests/sipass/

# Stop the Charon container and check its exit code.
echo "12. Stopping Charon container..."
docker stop "$CHARON_SIPASS_CONTAINER"
CHARON_SIPASS_EXIT_CODE=$(docker wait "$CHARON_SIPASS_CONTAINER")

if [ "$CHARON_SIPASS_EXIT_CODE" -ne 0 ]; then
  echo "ERROR: Charon SIPASS container exited with code $CHARON_SIPASS_EXIT_CODE"
  exit 1
fi

echo "=== E2E Tests Completed Successfully ==="
