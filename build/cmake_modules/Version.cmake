# read version

function(set_version version_file output_var)
    file(READ "${version_file}" version_data)

    string(REGEX MATCH "I2PD_VERSION_MAJOR ([0-9]*)" _ ${version_data})
    set(version_major ${CMAKE_MATCH_1})

    string(REGEX MATCH "I2PD_VERSION_MINOR ([0-9]*)" _ ${version_data})
    set(version_minor ${CMAKE_MATCH_1})

    string(REGEX MATCH "I2PD_VERSION_MICRO ([0-9]*)" _ ${version_data})
    set(version_micro ${CMAKE_MATCH_1})

    set(${output_var} "${version_major}.${version_minor}.${version_micro}" PARENT_SCOPE)
endfunction()
