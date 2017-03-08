
project(crypto.hpp CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS Off)

if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
endif()

if (WIN32)
    if (CMAKE_COMPILER_IS_GNUCXX)
        find_package(Boost COMPONENTS random system REQUIRED)
        include_directories(${Boost_INCLUDE_DIR})
        set(CRYPTO_HPP_RANDOM_LIBRARY ${Boost_LIBRARIES})
    endif()
    if (MSVC)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /permissive- /std:c++latest")
    endif()
endif()

add_executable(test_crypto test_crypto.cpp)
target_link_libraries(test_crypto ${CRYPTO_HPP_RANDOM_LIBRARY})


