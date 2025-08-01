#!/usr/bin/env bash
set -eo pipefail

venv=venv
pre_req_grep=(-e uv)

_install_pre=0

_py() {
    venv/bin/python "$@"
}

export UV_PROJECT_ENVIRONMENT="$venv"
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ $KEEP_SUBMODULES != 1 ]]; then
    git submodule sync
    git submodule update --init
fi

if ! [[ -d $venv ]]; then
    python -m venv "$venv"
    _install_pre=1
fi

if ! _py -m uv -V; then
    if ! _py -m pip -V; then
        python -m ensurepip || true
    fi
    _install_pre=1
fi

verlte() {
    local sorted
    sorted=$(echo -e "$1\n$2" | sort -V)
    [[ $1 = "$(head -n1 <<<"$sorted")" ]]
}

iptables_version=$(iptables --version | perl -pe 's/iptables v(\S+).*/$1/')
if verlte "$iptables_version" 1.8.10; then
    iptc_path=python-iptables-master
else
    iptc_path=python-iptables-bf
fi
iptc_dst=libs/python-iptables
rm "$iptc_dst" >/dev/null || true
ln -sf "$iptc_path" "$iptc_dst"

if [[ $_install_pre == 1 ]]; then
    _py -m pip install "uv ~= 0.8.3"
fi

_py -m uv sync --link-mode copy
