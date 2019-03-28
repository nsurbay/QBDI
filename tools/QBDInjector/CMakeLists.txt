
#############
##  Frida  ##
#############

set(FRIDA_INJECTOR_VERSION "12.3.2")
set(FRIDA_INJECTOR_ARCH "${ARCH}")

set(FRIDA_INJECTOR_SUFFIX "${OS}-${FRIDA_INJECTOR_ARCH}")

include(ExternalProject)

# Frida Core
# ==========
set(FRIDA_CORE_URL     "https://github.com/frida/frida/releases/download/${FRIDA_INJECTOR_VERSION}/frida-core-devkit-${FRIDA_INJECTOR_VERSION}-${FRIDA_INJECTOR_SUFFIX}.tar.xz")
set(FRIDA_CORE_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/frida-core")

ExternalProject_Add(frida-core
    URL               "${FRIDA_CORE_URL}"
    PREFIX            "${FRIDA_CORE_PREFIX}"
    BUILD_IN_SOURCE   1
    UPDATE_COMMAND    ""
    BUILD_COMMAND     ""
    INSTALL_COMMAND   ""
    CONFIGURE_COMMAND ""
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

# Frida Gum
# ==========
set(FRIDA_GUM_URL     "https://github.com/frida/frida/releases/download/${FRIDA_INJECTOR_VERSION}/frida-gum-devkit-${FRIDA_INJECTOR_VERSION}-${FRIDA_INJECTOR_SUFFIX}.tar.xz")
set(FRIDA_GUM_PREFIX  "${CMAKE_CURRENT_BINARY_DIR}/frida-gum")

ExternalProject_Add(frida-gum
    URL               "${FRIDA_GUM_URL}"
    PREFIX            "${FRIDA_GUM_PREFIX}"
    UPDATE_COMMAND    ""
    BUILD_COMMAND     ""
    CONFIGURE_COMMAND ""
    INSTALL_COMMAND   ""
)

ExternalProject_get_property(frida-gum SOURCE_DIR)
set(FRIDA_GUM_SOURCE_DIR "${SOURCE_DIR}")
set(FRIDA_GUM_LIBRARY
  "${FRIDA_GUM_SOURCE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}frida-gum${CMAKE_STATIC_LIBRARY_SUFFIX}")

set(FRIDA_GUM_INCLUDE_DIR
  "${FRIDA_GUM_SOURCE_DIR}/")

add_library(libfrida-gum INTERFACE)
add_dependencies(libfrida-gum frida-gum)
target_link_libraries(libfrida-gum INTERFACE ${FRIDA_GUM_LIBRARY})
target_include_directories(libfrida-gum INTERFACE ${FRIDA_GUM_INCLUDE_DIR})


################
##  Injector  ##
################

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -s")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -s")

set(QBDInjector_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/QBDInjector.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/QBDInjector_${OS}.cpp"
    )

add_executable(QBDInjector ${QBDInjector_SRC})
target_link_libraries(QBDInjector libfrida-core -ldl -lpthread -lresolv -lrt)
