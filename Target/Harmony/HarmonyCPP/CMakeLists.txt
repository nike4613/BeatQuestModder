cmake_minimum_required (VERSION 3.8)

set(LIBIL2CPP_SOURCE_ROOT "C:\\Program Files\\Unity\\Hub\\Editor\\2018.3.14f1\\Editor\\Data\\il2cpp\\libil2cpp" CACHE FILEPATH "The root of Unity's libil2cpp library" )

# Add source to this project's executable.
add_library (
	HarmonyCPP STATIC 
	"src/Harmony.cpp"	"include/Harmony.h"
	"src/icalls.cpp"	"include/icalls.h")
target_include_directories(HarmonyCPP PUBLIC "include")
target_include_directories(HarmonyCPP PRIVATE ${LIBIL2CPP_SOURCE_ROOT})

# TODO: Add tests and install targets if needed.
