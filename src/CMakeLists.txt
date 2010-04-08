set(PLUGIN_SRC
	main.c
)

add_library(spamassassin SHARED ${PLUGIN_SRC})
set_property(TARGET spamassassin PROPERTY VERSION ${PLUGIN_VERSION})
set_property(TARGET spamassassin PROPERTY SOVERSION ${PLUGIN_VERSION})
target_link_libraries(spamassassin ${SPMFILTER_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS spamassassin
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${LIBDIR}/spmfilter
)
