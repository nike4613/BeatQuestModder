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
macro(c_get_environment_vars OUT_V)
	message("Storing current environment in ${OUT_V}")
	execute_process(COMMAND ${CMAKE_COMMAND} -E environment OUTPUT_VARIABLE 0_CMAKE_ENVIRONMENT OUTPUT_STRIP_TRAILING_WHITESPACE)
	string(REPLACE ";" "$<SEMICOLON>" 1_CMAKE_ENVIRONMENT "${0_CMAKE_ENVIRONMENT}")
	string(REPLACE "\n" ";" ${OUT_V} "${1_CMAKE_ENVIRONMENT}")
endmacro()