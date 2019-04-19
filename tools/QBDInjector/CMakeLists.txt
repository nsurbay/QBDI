
#############
##  Frida  ##
#############

set(FRIDA_INJECTOR_VERSION "12.3.2")
set(FRIDA_INJECTOR_ARCH "${ARCH}")

if ("${OS}" STREQUAL "win")
    set(FRIDA_INJECTOR_SUFFIX "windows-${FRIDA_INJECTOR_ARCH}.exe")
    set(FRIDA_INJECTOR_CUSTOM_OPT
        DOWNLOAD_NO_EXTRACT "y"
        UPDATE_COMMAND "<DOWNLOADED_FILE>" "x" "-y" "-o<SOURCE_DIR>")
else()
    set(FRIDA_INJECTOR_SUFFIX "${OS}-${FRIDA_INJECTOR_ARCH}.tar.xz")
    set(FRIDA_INJECTOR_CUSTOM_OPT "")
endif()

include(ExternalProject)

# Frida Core
# ==========
set(FRIDA_CORE_URL     "https://github.com/frida/frida/releases/download/${FRIDA_INJECTOR_VERSION}/frida-core-devkit-${FRIDA_INJECTOR_VERSION}-${FRIDA_INJECTOR_SUFFIX}")
set(FRIDA_CORE_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/frida-core")

ExternalProject_Add(frida-core
    URL                 "${FRIDA_CORE_URL}"
    PREFIX              "${FRIDA_CORE_PREFIX}"
    DOWNLOAD_NAME       "frida-core-devkit-${FRIDA_INJECTOR_VERSION}-${FRIDA_INJECTOR_SUFFIX}"
    BUILD_IN_SOURCE     1
    ${FRIDA_INJECTOR_CUSTOM_OPT}
    BUILD_COMMAND       ""
    INSTALL_COMMAND     ""
    CONFIGURE_COMMAND   ""
)

ExternalProject_get_property(frida-core SOURCE_DIR)
set(FRIDA_CORE_SOURCE_DIR "${SOURCE_DIR}")
set(FRIDA_CORE_LIBRARY
  "${FRIDA_CORE_SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}frida-core${CMAKE_STATIC_LIBRARY_SUFFIX}")

set(FRIDA_CORE_INCLUDE_DIR
  "${FRIDA_CORE_SOURCE_DIR}/")

add_library(libfrida-core INTERFACE)
add_dependencies(libfrida-core frida-core)
target_link_libraries(libfrida-core INTERFACE ${FRIDA_CORE_LIBRARY})
target_include_directories(libfrida-core INTERFACE ${FRIDA_CORE_INCLUDE_DIR})

## Frida Gum
## ==========
#set(FRIDA_GUM_URL     "https://github.com/frida/frida/releases/download/${FRIDA_INJECTOR_VERSION}/frida-gum-devkit-${FRIDA_INJECTOR_VERSION}-${FRIDA_INJECTOR_SUFFIX}.tar.xz")
#set(FRIDA_GUM_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/frida-gum")
#
#ExternalProject_Add(frida-gum
#    URL               "${FRIDA_GUM_URL}"
#    PREFIX            "${FRIDA_GUM_PREFIX}"
#    UPDATE_COMMAND    ""
#    BUILD_COMMAND     ""
#    CONFIGURE_COMMAND ""
#    INSTALL_COMMAND   ""
#)
#
#ExternalProject_get_property(frida-gum SOURCE_DIR)
#set(FRIDA_GUM_SOURCE_DIR "${SOURCE_DIR}")
#set(FRIDA_GUM_LIBRARY
#  "${FRIDA_GUM_SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}frida-gum${CMAKE_STATIC_LIBRARY_SUFFIX}")
#
#set(FRIDA_GUM_INCLUDE_DIR
#  "${FRIDA_GUM_SOURCE_DIR}/")
#
#add_library(libfrida-gum INTERFACE)
#add_dependencies(libfrida-gum frida-gum)
#target_link_libraries(libfrida-gum INTERFACE ${FRIDA_GUM_LIBRARY})
#target_include_directories(libfrida-gum INTERFACE ${FRIDA_GUM_INCLUDE_DIR})

if ("${OS}" STREQUAL "win")
    # include getopt for VS
    ExternalProject_Add(vs_getopt
        GIT_REPOSITORY      "https://github.com/skandhurkat/Getopt-for-Visual-Studio.git"
        GIT_TAG             "2a6e4fb7f501b863c5bc32dd6e7277f110f1e14b"
        CONFIGURE_COMMAND   ""
        BUILD_COMMAND       ""
        INSTALL_COMMAND     ""
    )

    ExternalProject_get_property(vs_getopt SOURCE_DIR)
    set(VS_GETOPT_SOURCE_DIR "${SOURCE_DIR}")
endif()


################
##  Injector  ##
################

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")

set(QBDInjector_SRC
        "${CMAKE_CURRENT_SOURCE_DIR}/src/Injector.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/Injector_${OS}.cpp"
        "${CMAKE_CURRENT_SOURCE_DIR}/src/common_${OS}.c"
    )

add_executable(QBDInjector ${QBDInjector_SRC})
target_link_libraries(QBDInjector libfrida-core)
target_include_directories(QBDInjector PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
if ("${OS}" STREQUAL "win")
    target_include_directories(QBDInjector PRIVATE "${VS_GETOPT_SOURCE_DIR}")
    add_dependencies(QBDInjector vs_getopt)
else()
    target_link_libraries(QBDInjector -ldl -lpthread -lresolv -lrt)
endif()

install(TARGETS QBDInjector DESTINATION bin COMPONENT QBDInjector)


################
##  Injected  ##
################

set(QBDInjected_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Injected.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/Injected_${OS}.c"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/common_${OS}.c"
    )

add_library(QBDInjected ${QBDInjected_SRC})
target_include_directories(QBDInjected PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")

install(TARGETS QBDInjected ARCHIVE DESTINATION lib COMPONENT QBDInjector)
install(FILES include/QBDInjector.h DESTINATION include/)

