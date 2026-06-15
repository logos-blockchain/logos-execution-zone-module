#!/usr/bin/env bash
#
# Execute the execution-zone-module doc-test end-to-end and regenerate its Markdown.
#
# There is one spec:
#   logos-execution-zone-runtime.test.yaml — packages this module as an .lgx,
#       installs it with lgpm, and drives it through a headless logoscore daemon,
#       calling its wallet-free methods (name/version and the base58 account-id
#       codec) and asserting on the output.
#
# The runner is the shared `doctest` CLI
# (https://github.com/logos-co/logos-doctest), invoked directly via its flake.
# The spec runs into ./outputs/ via --output-dir; `doctest generate` renders the
# .md; `doctest clean` then strips build artifacts, keeping only the .md.
#
# To run against a local logos-doctest checkout instead of the published flake,
# set DOCTEST, e.g.:  DOCTEST="nix run path:../../logos-doctest --" ./run.sh
#
set -euo pipefail

# Run from this doctests/ directory regardless of where the script is invoked from.
cd "$(dirname "$0")"

# The doctest CLI. Override by exporting DOCTEST (space-separated command).
read -r -a DOCTEST <<< "${DOCTEST:-nix run github:logos-co/logos-doctest --}"
OUTPUT_DIR="./outputs"

# Build the doc-test against THIS repo's current commit rather than the latest
# published flake. The spec pins `github:logos-blockchain/logos-execution-zone-module{release}`
# to $COMMIT via --release-for, so it packages exactly what is checked out here.
# Override by exporting COMMIT (e.g. a tag), or set COMMIT="" to fall back to
# latest master.
#
# Note: nix fetches the commit from the GitHub remote, so $COMMIT must be pushed
# to logos-blockchain/logos-execution-zone-module. A local-only / uncommitted HEAD
# won't resolve; export COMMIT="" (or push first) in that case.
#
# This is a private repo, so nix must be able to authenticate to GitHub. If the
# build 404s on the commit even after pushing, add a token to ~/.config/nix/nix.conf:
#   access-tokens = github.com=ghp_yourtoken
COMMIT="${COMMIT-$(git rev-parse HEAD)}"
RELEASE_FOR=()
if [ -n "${COMMIT}" ]; then
  RELEASE_FOR=(--release-for "logos-execution-zone-module=${COMMIT}")
  echo "==> Pinning logos-execution-zone-module to ${COMMIT}"
else
  echo "==> COMMIT empty; building from latest logos-execution-zone-module master"
fi

echo "==> Clearing previous ${OUTPUT_DIR}/"
# A prior run copies module artifacts out of the read-only nix store, so the
# directories land read-only (r-x) too. `rm -rf` can't delete files inside a
# directory it can't write to, so restore write permission first.
if [ -e "${OUTPUT_DIR}" ]; then
  chmod -R u+w "${OUTPUT_DIR}" 2>/dev/null || true
fi
rm -rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"

for spec in *.test.yaml; do
  name="$(basename "${spec%.test.yaml}")"
  echo "==> Running ${spec} into ${OUTPUT_DIR}/"
  # ${RELEASE_FOR[@]+...} guards the expansion so an empty array doesn't trip
  # `set -u` on older bash (e.g. macOS's stock 3.2).
  "${DOCTEST[@]}" run "${spec}" \
    --verbose \
    --continue-on-fail \
    ${RELEASE_FOR[@]+"${RELEASE_FOR[@]}"} \
    --output-dir "${OUTPUT_DIR}/"

  echo "==> Generating ${OUTPUT_DIR}/${name}.md"
  "${DOCTEST[@]}" generate "${spec}" \
    ${RELEASE_FOR[@]+"${RELEASE_FOR[@]}"} \
    -o "${OUTPUT_DIR}/${name}.md"
done

echo "==> Cleaning build artifacts from ${OUTPUT_DIR}/ (keeps .md)"
"${DOCTEST[@]}" clean "${OUTPUT_DIR}" --verbose

echo "==> Done. Rendered docs are in ${OUTPUT_DIR}/"
