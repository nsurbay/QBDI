cmake_minimum_required (VERSION 3.2)
project(QBDInjector_test)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fvisibility=hidden")

# TODO change path
set(QBDI_INCLUDE_DIRS "/home/kaname/git/QBDI/git/include" "/home/kaname/git/QBDI/git/tools/QBDInjector/include")
set(QBDI_LIB_DIRS "/home/kaname/git/QBDI/git/build" "/home/kaname/git/QBDI/git/build/tools/QBDInjector")
find_library(QBDI_LIB QBDI HINTS "/home/kaname/git/QBDI/git/build/")

set(SOURCELIB "test_injector.c")

add_library(qbdi_injector SHARED ${SOURCELIB})
target_include_directories(qbdi_injector PUBLIC ${QBDI_INCLUDE_DIRS})
target_link_directories(qbdi_injector PUBLIC ${QBDI_LIB_DIRS})
target_link_libraries(qbdi_injector PUBLIC ${QBDI_LIB} -Wl,--whole-archive /home/kaname/git/QBDI/git/build/tools/QBDInjector/libQBDInjector.a -Wl,--no-whole-archive)

