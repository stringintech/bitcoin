#!/usr/bin/env bash
#
# Copyright (c) 2026-present The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

export LC_ALL=C.UTF-8

export CONTAINER_NAME=ci_native_script_trace
export CI_IMAGE_NAME_TAG="mirror.gcr.io/ubuntu:24.04"
export PACKAGES="python3-zmq python3-pip"
export PIP_PACKAGES="--break-system-packages pycapnp"
export GOAL="install"
# ENABLE_SCRIPT_TRACE is off by default, so the script trace hooks are compiled out of every
# other job. This one builds them in, covering both the kernel API surface (test_kernel) and
# the interpreter-level unit tests (test_bitcoin).
export BITCOIN_CONFIG="\
  --preset=dev-mode \
  -DENABLE_SCRIPT_TRACE=ON \
"
