#!/usr/bin/env bash
# 使用自编译 OpenSSL 构建/运行 crypto-offload（CMP 需 3.x 且含 CMP 符号）。
# 用法: source scripts/benchmark/env_openssl.sh [30|35]
# 默认 35 → /opt/openssl35x

set -euo pipefail

_variant="${1:-35}"
case "${_variant}" in
  30|35)
    OPENSSL_ROOT="/opt/openssl${_variant}x"
    ;;
  *)
    echo "usage: source env_openssl.sh [30|35]" >&2
    return 1 2>/dev/null || exit 1
    ;;
esac

if [[ ! -d "${OPENSSL_ROOT}/lib" ]]; then
  echo "OPENSSL_ROOT not found: ${OPENSSL_ROOT}" >&2
  return 1 2>/dev/null || exit 1
fi

export OPENSSL_DIR="${OPENSSL_ROOT}"
export OPENSSL_LIB_DIR="${OPENSSL_ROOT}/lib"
export OPENSSL_INCLUDE_DIR="${OPENSSL_ROOT}/include"
export PATH="${OPENSSL_ROOT}/bin:${PATH}"

if [[ -d "${OPENSSL_ROOT}/lib/pkgconfig" ]]; then
  export PKG_CONFIG_PATH="${OPENSSL_ROOT}/lib/pkgconfig${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
fi

# 运行时 libloading(CMP) + 动态链接 libssl/libcrypto 均走同一套库
export LD_LIBRARY_PATH="${OPENSSL_ROOT}/lib${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"

# 可选：本地 OpenSSL 源码树（含 CMP 测试 DER，见 test/recipes/65-test_cmp_protect_data/）
if [[ -d /home/ubuntu/github/openssl-3.5.6 ]]; then
  export OPENSSL_SRC="${OPENSSL_SRC:-/home/ubuntu/github/openssl-3.5.6}"
elif [[ -d /home/ubuntu/github/openssl-3.0.20 ]]; then
  export OPENSSL_SRC="${OPENSSL_SRC:-/home/ubuntu/github/openssl-3.0.20}"
fi

echo "OPENSSL_DIR=${OPENSSL_DIR}"
if [[ -n "${OPENSSL_SRC:-}" ]]; then
  echo "OPENSSL_SRC=${OPENSSL_SRC}"
fi
echo "LD_LIBRARY_PATH=${LD_LIBRARY_PATH}"
"${OPENSSL_ROOT}/bin/openssl" version 2>/dev/null || openssl version
