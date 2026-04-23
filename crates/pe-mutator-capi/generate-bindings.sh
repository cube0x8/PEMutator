#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
workspace_root="$(cd "$script_dir/../.." && pwd)"
output_dir="$script_dir/include"

mkdir -p "$output_dir"

cbindgen "$workspace_root" \
  --config "$script_dir/cbindgen.toml" \
  --crate pe-mutator-capi \
  --output "$output_dir/pe_mutator.h"
