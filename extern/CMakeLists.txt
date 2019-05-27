set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "Disable Capstone Arches" FORCE)
set(CAPSTONE_ARM_SUPPORT ON CACHE BOOL "Enable Capstone ARM support" FORCE)
set(CAPSTONE_BUILD_STATIC_RUNTIME OFF CACHE BOOL "Disable Capstone static runtime build" FORCE)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "Disable Capstone shared build" FORCE)

add_subdirectory("capstone")

set(CAPSTONE_INCLUDE_DIR "${CMAKE_CURRENT_LIST_DIR}/capstone/include" PARENT_SCOPE)