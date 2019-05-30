cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (BeatQuestModder 
	"src/BeatQuestModder.cpp" "include/BeatQuestModder.h"
	"src/bqm/capstone/Handle.cpp" "include/bqm/capstone/Handle.h"
	"include/buffer.h")
add_dependencies(BeatQuestModder llvm)
target_include_directories(BeatQuestModder BEFORE PUBLIC "include")
target_include_directories(BeatQuestModder BEFORE PRIVATE ${CAPSTONE_INCLUDE_DIR})
target_include_directories(BeatQuestModder BEFORE PRIVATE ${LLVM_INCLUDE_DIR})
target_link_libraries(BeatQuestModder capstone-static)
# TODO: Add tests and install targets if needed.
