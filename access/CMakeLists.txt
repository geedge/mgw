add_executable(mgw src/main.cpp src/vpn_monitor.cpp src/nat.cpp src/ip_mgr.cpp src/udp_server.cpp)

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


add_executable(test_tun test/test_tun.cpp)

target_include_directories(test_tun PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(test_tun common)
target_link_libraries(test_tun pthread dl
		MESA_handle_logger
		MESA_prof_load
		MESA_htable
		)

add_executable(test_htable test/test_MESA_htable.cpp)

target_include_directories(test_htable PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)

target_link_libraries(test_htable common)
target_link_libraries(test_htable pthread dl
		MESA_handle_logger
		MESA_prof_load
		MESA_htable
		MESA_field_stat
		)