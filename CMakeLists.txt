#
# Copyright (c) 2020 Nordic Semiconductor
#
# SPDX-License-Identifier: LicenseRef-BSD-5-Clause-Nordic
#

#cmake_minimum_required(VERSION 3.8.2)
#
#include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
##include($ENV{ZEPHYR_BASE}/../nrf/cmake/boilerplate.cmake)
#include(../../../cmake/boilerplate.cmake)
#project(IoTConnectSDK)
#
#target_sources(app PRIVATE src/main.c)
#zephyr_include_directories(src)
#
#include_directories(src/orientation_detector)
#target_sources(app PRIVATE IoTConnect/src/IoTConnectSDK.c)

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(https_client)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
#target_sources(app PRIVATE src/main_test.c)
target_sources(app PRIVATE IoTConnect/src/IoTConnectSDK.c)
# NORDIC SDK APP END
