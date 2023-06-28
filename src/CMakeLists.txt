cmake_minimum_required(VERSION 3.0)

project(pcap_test)

aux_source_directory(. SRC_DIRS)

#指定链接库的路径，必须要放在 add_executable前面，否则不会去这里查找库
LINK_DIRECTORIES(/home/nope/test/pcap_test/3th/lib)

add_executable(pcap_test ${SRC_DIRS})

target_compile_features(pcap_test PUBLIC cxx_auto_type)


target_include_directories(pcap_test PUBLIC ${PROJECT_SOURCE_DIR}/../3th/include)

target_link_libraries(pcap_test  PRIVATE ${CMAKE_DL_LIBS} libpcap.so  pthread)

install(TARGETS pcap_test DESTINATION bin)
