if(HAS_QBDIPRELOAD)
    # Add QBDI preload library
    add_subdirectory(QBDIPreload)

    # Add validator
    add_subdirectory(validator)

    # Add pyqbdi
    add_subdirectory(pyqbdi)
endif()

# Add QBDInjector
add_subdirectory(QBDInjector)
