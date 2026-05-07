variable "CHARON_IMAGE" {
  default = "charon-image"
}

variable "PLAYWRIGHT_IMAGE" {
  default = "charon-playwright-image"
}

group "default" {
  targets = ["charon", "playwright"]
}

target "charon" {
  context    = "."
  dockerfile = "Dockerfile"
  target     = "production"
  args = {
    CHARON_BUILD_FLAGS = "-cover -race -covermode atomic"
    VITE_COVERAGE      = "true"
    VITE_E2E_TESTS     = "true"
  }
  tags = ["${CHARON_IMAGE}"]
}

target "playwright" {
  context    = "."
  dockerfile = "playwright.dockerfile"
  tags       = ["${PLAYWRIGHT_IMAGE}"]
}
