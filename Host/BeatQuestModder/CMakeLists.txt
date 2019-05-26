# CMakeList.txt : CMake project for BeatQuestModder, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

# Add source to this project's executable.
add_executable (BeatQuestModder "src/BeatQuestModder.cpp" "include/BeatQuestModder.h")
target_include_directories(BeatQuestModder PUBLIC "include")

# TODO: Add tests and install targets if needed.
