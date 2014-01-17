set(SPAMCTL_SRC
	spamctl.c
)

set(SPAMQ_SRC
	spamq.c
)

set(PLUGIN_SRC
	main.c
)

add_library(spamassassin SHARED ${PLUGIN_SRC})
set_property(TARGET spamassassin PROPERTY VERSION ${PLUGIN_VERSION})
set_property(TARGET spamassassin PROPERTY SOVERSION ${PLUGIN_So_VERSION})
target_link_libraries(spamassassin ${SPMFILTER_LIBRARIES})

#add_executable(smf-spamctl ${SPAMCTL_SRC})
#target_link_libraries(smf-spamctl ${SPMFILTER_LIBRARIES})

#add_executable(smf-spamq ${SPAMQ_SRC})

#install(TARGETS smf-spamctl smf-spamq spamassassin
install(TARGETS spamassassin
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${SPMFILTER_LIBRARY_DIRS}
)
