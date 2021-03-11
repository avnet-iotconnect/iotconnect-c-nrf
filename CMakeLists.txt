#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

cmake_minimum_required(VERSION 3.8.2)

include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
#include($ENV{ZEPHYR_BASE}/../nrf/cmake/boilerplate.cmake)
include(../../../cmake/boilerplate.cmake)
project(IoTConnectSDK)

target_sources(app PRIVATE src/main.c)
zephyr_include_directories(src)

include_directories(src/orientation_detector)
target_sources(app PRIVATE IoTConnect/src/IoTConnectSDK.c)
