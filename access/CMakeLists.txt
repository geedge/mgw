add_executable(mgw src/main.cpp src/tun.cpp)

target_include_directories(mgw PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(mgw common)
target_link_libraries(mgw pthread dl
		MESA_handle_logger
		MESA_prof_load
		MESA_htable 
        wiredcfg
		MESA_field_stat
        maatframe)

# target_link_libraries(tfe -Wl,--whole-archive http -Wl,--no-whole-archive)
# target_link_libraries(tfe -Wl,--whole-archive pangu-http -Wl,--no-whole-archive)


add_executable(test_maat_redis test/test_maat_redis.cpp)

target_include_directories(test_maat_redis PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(test_maat_redis common)
target_link_libraries(test_maat_redis pthread dl
		MESA_handle_logger
		MESA_prof_load
		MESA_htable 
        wiredcfg
		MESA_field_stat
        maatframe)