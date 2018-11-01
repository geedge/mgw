add_library(common src/mgw_utils.cpp)
target_include_directories(common PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
target_link_libraries(common MESA_handle_logger)