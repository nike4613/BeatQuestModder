# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.14)

LIST(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
project ("BeatQuestModder")

option(COMPILE_USE_LTO "Enable Link Time Optimization" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CheckIPOSupported)
check_ipo_supported(RESULT IPO_SUPPORTED)
if (COMPILE_USE_LTO)
	if (IPO_SUPPORTED)
		set(CMAKE_INTERPROCEDURAL_OPTIMIZATION ON)
	else()
		message("LTO was requested, but the compiler toolchain doesn't support it.")
	endif()
endif()

# Include libraries
add_subdirectory ("extern")

# Include sub-projects.
add_subdirectory ("Host")
add_subdirectory ("Target")
