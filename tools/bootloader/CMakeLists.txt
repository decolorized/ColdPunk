# ESP-IDF project that exists only for its bootloader: build-idf-bootloader
# and build-secure run `idf.py bootloader` here (ESP-IDF 5.5.5, the version
# the Arduino core 3.3.11 is built from). The app part is never used - the
# firmware itself still comes from the Arduino build.
cmake_minimum_required(VERSION 3.16)
# Only what the empty main needs: a short configure, no network components.
set(COMPONENTS main)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(coldpunk_bootloader)
