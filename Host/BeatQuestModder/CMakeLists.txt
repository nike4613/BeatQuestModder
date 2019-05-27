cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (BeatQuestModder 
	"src/BeatQuestModder.cpp" "include/BeatQuestModder.h")
target_include_directories(BeatQuestModder PUBLIC "include")
target_include_directories(BeatQuestModder BEFORE PRIVATE ${CAPSTONE_INCLUDE_DIR})
message(${CAPSTONE_INCLUDE_DIR})
target_link_libraries(BeatQuestModder capstone-static)
# TODO: Add tests and install targets if needed.
