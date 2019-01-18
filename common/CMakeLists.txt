add_library(common src/mgw_utils.cpp src/mgw_tun.cpp src/mgw_socket.cpp src/ip_locator.cpp)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(common MESA_handle_logger IPLocator-static)