#!/usr/bin/env bash
set -eo pipefail

script_dir=$(dirname "${BASH_SOURCE[0]}")
module_path=$(realpath --relative-to="$script_dir" "$1")
module="${module_path/\//.}"
module="${module%.py}"
echo "$module" 1>&2
cd "$script_dir"

if [[ $UPDATE_VENV == 1 ]]; then
    ./venv-update.sh
fi

system_libs=$(
    ldconfig -p | \
    perl -ne 'next unless /xtables/; s/.* => (\S+lib\/\S+).*/$1/; print' | \
    while read -r lib; do dirname "$lib"; done | \
    uniq | tr '\n' ':'
)
export IPTABLES_LIBDIR="libs/python-iptables:${system_libs%:}"
echo "Library search dir: $IPTABLES_LIBDIR" 1>&2

venv/bin/python -m "$module"
