cmake_minimum_required(VERSION 3.0)

project(pcap_test)

#SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -fPIC   -Wall -Wl,-rpath=/home/nope/test/pcap_test/3th/lib") 
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")
# 禁用安装时的RPATH设置
set(CMAKE_SKIP_INSTALL_RPATH TRUE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)

# 设置链接路径为RPATH
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

# 设置所需的RPATH
set(CMAKE_INSTALL_RPATH "/home/nope/test/pcap_test/3th/lib")

aux_source_directory(. SRC_DIRS)

#指定链接库的路径，必须要放在 add_executable前面，否则不会去这里查找库
LINK_DIRECTORIES(/home/nope/test/pcap_test/3th/lib)

add_executable(pcap_test ${SRC_DIRS})

target_compile_features(pcap_test PUBLIC cxx_auto_type)


target_include_directories(pcap_test PUBLIC ${PROJECT_SOURCE_DIR}/../3th/include)

target_link_libraries(pcap_test  PRIVATE ${CMAKE_DL_LIBS} libpcap.so  pthread)

#install(TARGETS pcap_test DESTINATION bin)
