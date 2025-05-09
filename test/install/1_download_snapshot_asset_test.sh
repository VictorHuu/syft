. test_harness.sh

DOWNLOAD_SNAPSHOT_POSITIVE_CASES=0

# helper for asserting test_positive_snapshot_download_asset positive cases
test_positive_snapshot_download_asset() {
  os="$1"
  arch="$2"
  format="$3"

  # for troubleshooting
  # log_set_priority 10

  name=${PROJECT_NAME}
  github_download=$(snapshot_download_url)
  version=$(snapshot_version)

  tmpdir=$(mktemp -d)

  actual_filepath=$(download_asset "${github_download}" "${tmpdir}" "${name}" "${os}" "${arch}" "${version}" "${format}" )

  assertFileExists "${actual_filepath}" "download_asset os=${os} arch=${arch} format=${format}"

  assertFilesEqual \
    "$(snapshot_dir)/${name}_${version}_${os}_${arch}.${format}" \
    "${actual_filepath}" \
    "unable to download os=${os} arch=${arch} format=${format}"

  ((DOWNLOAD_SNAPSHOT_POSITIVE_CASES++))

  rm -rf -- "$tmpdir"
}


test_download_snapshot_asset_exercised_all_assets() {
  expected=$(snapshot_assets_count)

  assertEquals "${expected}" "${DOWNLOAD_SNAPSHOT_POSITIVE_CASES}" "did not download all possible assets (missing an os/arch/format variant?)"
}

# helper for asserting download_asset negative cases
test_negative_snapshot_download_asset() {
  os="$1"
  arch="$2"
  format="$3"

  # for troubleshooting
  # log_set_priority 10

  name=${PROJECT_NAME}
  github_download=$(snapshot_download_url)
  version=$(snapshot_version)

  tmpdir=$(mktemp -d)

  actual_filepath=$(download_asset "${github_download}" "${tmpdir}" "${name}" "${os}" "${arch}" "${version}" "${format}")

  assertEquals ""  "${actual_filepath}" "unable to download os=${os} arch=${arch} format=${format}"

  rm -rf -- "$tmpdir"
}

test_sboms_have_packages() {
  if ! command -v jq &> /dev/null; then
    echo "jq command not found. Please install jq or ensure it is in your PATH."
    exit 1
  fi

  find "$(snapshot_dir)/" -name "*.sbom" -print0 | while IFS= read -r -d '' file; do
      count=$(cat "$file" | jq ".artifacts | length")
      if [ "$count" -lt 80 ]; then
          echo "not enough packages found for file: $file"
          exit 1
      fi
  done
}


worker_pid=$(setup_snapshot_server)
trap 'teardown_snapshot_server ${worker_pid}' EXIT

# exercise all possible assets
run_test_case test_positive_snapshot_download_asset "linux" "amd64" "sbom"
run_test_case test_positive_snapshot_download_asset "linux" "amd64" "tar.gz"
run_test_case test_positive_snapshot_download_asset "linux" "amd64" "rpm"
run_test_case test_positive_snapshot_download_asset "linux" "amd64" "deb"
run_test_case test_positive_snapshot_download_asset "linux" "arm64" "sbom"
run_test_case test_positive_snapshot_download_asset "linux" "arm64" "tar.gz"
run_test_case test_positive_snapshot_download_asset "linux" "arm64" "rpm"
run_test_case test_positive_snapshot_download_asset "linux" "arm64" "deb"
run_test_case test_positive_snapshot_download_asset "linux" "ppc64le" "sbom"
run_test_case test_positive_snapshot_download_asset "linux" "ppc64le" "tar.gz"
run_test_case test_positive_snapshot_download_asset "linux" "ppc64le" "rpm"
run_test_case test_positive_snapshot_download_asset "linux" "ppc64le" "deb"
run_test_case test_positive_snapshot_download_asset "linux" "s390x" "sbom"
run_test_case test_positive_snapshot_download_asset "linux" "s390x" "tar.gz"
run_test_case test_positive_snapshot_download_asset "linux" "s390x" "rpm"
run_test_case test_positive_snapshot_download_asset "linux" "s390x" "deb"

run_test_case test_positive_snapshot_download_asset "darwin" "amd64" "sbom"
run_test_case test_positive_snapshot_download_asset "darwin" "amd64" "tar.gz"
run_test_case test_positive_snapshot_download_asset "darwin" "arm64" "sbom"
run_test_case test_positive_snapshot_download_asset "darwin" "arm64" "tar.gz"

run_test_case test_positive_snapshot_download_asset "windows" "amd64" "sbom"
run_test_case test_positive_snapshot_download_asset "windows" "amd64" "zip"
# note: the mac signing process produces a dmg which is not part of the snapshot process (thus is not exercised here)

# let's make certain we covered all assets that were expected
run_test_case test_download_snapshot_asset_exercised_all_assets

# make certain we handle missing assets alright
run_test_case test_negative_snapshot_download_asset "bogus" "amd64" "zip"

# given we've downloaded the SBOMs, sanity check that they have a reasonable number of packages
run_test_case test_sboms_have_packages

trap - EXIT
teardown_snapshot_server "${worker_pid}"
