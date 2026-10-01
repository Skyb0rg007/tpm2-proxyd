#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Skye Soss <skye@soss.website>
#
# SPDX-License-Identifier: Apache-2.0
#
# Run the application tests (or the ones named as arguments, e.g.
# `tpm2-openssl`) and summarize. Exits non-zero if any test failed, or if
# REQUIRE_ALL is set and any was skipped. See lib.sh for the environment
# variables they read.

set -uo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
if [ "$#" -eq 0 ]; then
  tests=()
  for t in "$here"/*.sh; do
    case "$(basename "$t")" in lib.sh | run.sh) ;; *) tests+=("$t") ;; esac
  done
else
  tests=()
  for t in "$@"; do tests+=("$here/${t%.sh}.sh"); done
fi

passed=() skipped=() failed=()
for t in "${tests[@]}"; do
  name="$(basename "$t" .sh)"
  bash "$t"
  case $? in
  0) passed+=("$name") ;;
  77) skipped+=("$name") ;;
  *) failed+=("$name") ;;
  esac
done

echo "passed: ${passed[*]:-none}"
echo "skipped: ${skipped[*]:-none}"
echo "failed: ${failed[*]:-none}"
[ "${#failed[@]}" -eq 0 ] || exit 1
[ -z "${REQUIRE_ALL:-}" ] || [ "${#skipped[@]}" -eq 0 ] || exit 1
