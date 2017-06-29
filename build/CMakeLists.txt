PROJECT(spice_sniffer)

SET(SRC_LIST ../src/main.cpp
             ../src/lib/utils/Time.cpp ../src/lib/utils/CmdlineOption.cpp
             ../src/lib/net/Sniffer.cpp)

SET(CMAKE_CXX_COMPILER "clang++")
#SET(CMAKE_CXX_FLAGS "-std=c++11 -Werror -Weverything -Wno-documentation -Wno-disabled-macro-expansion -Wno-float-equal -Wno-c++98-compat -Wno-c++98-compat-pedantic -Wno-global-constructors -Wno-exit-time-destructors -Wno-missing-prototypes -Wno-padded -Wno-old-style-cast -Wno-weak-vtables")
#SET(CMAKE_CXX_FLAGS "-std=c++11 -O3")
SET(CMAKE_CXX_FLAGS "-std=c++11 -O0")
SET(CMAKE_BUILD_TYPE debug)
ADD_EXECUTABLE(spice_sniffer ${SRC_LIST})
