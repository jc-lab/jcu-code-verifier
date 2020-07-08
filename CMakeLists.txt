cmake_minimum_required (VERSION 3.12)
project(jcu-code-verifier CXX)

set(CMAKE_CXX_STANDARD 14)

add_subdirectory(jcu-file)
add_subdirectory(jcu-random)

# <CONAN BUILD>

set(SRC_FILES
		${CMAKE_CURRENT_SOURCE_DIR}/include/jcu_code_verifier/constants.h
		${CMAKE_CURRENT_SOURCE_DIR}/include/jcu_code_verifier/code_verifier.h
		${CMAKE_CURRENT_SOURCE_DIR}/include/jcu_code_verifier/provider.h
		${CMAKE_CURRENT_SOURCE_DIR}/src/code_verifier.cc
		)

if(WIN32)
	set(SRC_PLATFORM_FILES
			${CMAKE_CURRENT_SOURCE_DIR}/src/windows/win_trust_provider.cc
			)
endif()
if(UNIX)
	set(SRC_PLATFORM_FILES
			${CMAKE_CURRENT_SOURCE_DIR}/src/linux/urandom-random-provider.cc
			)
endif()

add_library(${PROJECT_NAME} ${SRC_FILES} ${SRC_PLATFORM_FILES})
target_include_directories(${PROJECT_NAME} PUBLIC
		$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
		$<INSTALL_INTERFACE:include>)

target_link_libraries(${PROJECT_NAME} jcu-file)

if(WIN32)
	target_link_libraries(${PROJECT_NAME} wintrust.lib crypt32.lib)
endif()

option(jcu_code_verifier_BUILD_TESTS "Build tests" ON)

if(jcu_code_verifier_BUILD_TESTS)
	set(gtest_force_shared_crt ON CACHE BOOL "")

	include(FetchContent)

	FetchContent_Declare(
			googletest
			GIT_REPOSITORY https://github.com/google/googletest.git
			GIT_TAG        release-1.10.0
	)

	FetchContent_GetProperties(googletest)

	if(NOT googletest_POPULATED)
		FetchContent_Populate(googletest)
		add_subdirectory(${googletest_SOURCE_DIR} ${googletest_BINARY_DIR})
	endif()

	enable_testing()
	add_subdirectory(test)
endif()
