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

# generate list for use with ExternalProject_Add
macro(c_get_command_vars OUT_V)
	get_cmake_property(CACHE_VARS CACHE_VARIABLES)
	set(${OUT_V} "")
	message("Storing current variables in ${OUT_V}")
	foreach(CACHE_VAR ${CACHE_VARS})
		get_property(CACHE_VAR_HELPSTRING CACHE ${CACHE_VAR} PROPERTY HELPSTRING)
		get_property(CACHE_VAR_TYPE CACHE ${CACHE_VAR} PROPERTY TYPE)
		if(NOT CACHE_VAR_TYPE STREQUAL "INTERNAL" AND NOT CACHE_VAR_TYPE STREQUAL "STATIC")
			if(CACHE_VAR_TYPE STREQUAL "UNINITIALIZED")
				set(CACHE_VAR_TYPE)
			else()
				set(CACHE_VAR_TYPE :${CACHE_VAR_TYPE})
			endif()
			list(APPEND ${OUT_V} "-D${CACHE_VAR}${CACHE_VAR_TYPE}=${${CACHE_VAR}}")
		endif()
	endforeach()
endmacro()

# generate list of environment variables
execute_process(COMMAND ${CMAKE_COMMAND} -E environment OUTPUT_VARIABLE 0_CMAKE_ENVIRONMENT OUTPUT_STRIP_TRAILING_WHITESPACE)
string(REPLACE ";" "$<SEMICOLON>" 1_CMAKE_ENVIRONMENT "${0_CMAKE_ENVIRONMENT}")
string(REPLACE "\n" ";" CMAKE_ENVIRONMENT "${1_CMAKE_ENVIRONMENT}")

# Include libraries
add_subdirectory ("extern")

# Include sub-projects.
add_subdirectory ("Host")
add_subdirectory ("Target")
