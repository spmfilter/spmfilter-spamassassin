set(LIBERATOR_SRC
	liberator.c
)

set(PLUGIN_SRC
	main.c
)

add_library(spamassassin SHARED ${PLUGIN_SRC})
set_property(TARGET spamassassin PROPERTY VERSION ${PLUGIN_VERSION})
set_property(TARGET spamassassin PROPERTY SOVERSION ${PLUGIN_VERSION})
target_link_libraries(spamassassin ${SPMFILTER_LIBRARIES} ${GLIB2_LIBRARIES})

add_executable(smf-spamliberator ${LIBERATOR_SRC})
target_link_libraries(smf-spamliberator ${GLIB2_LIBRARIES} ${SPMFILTER_LIBRARIES})

install(TARGETS smf-spamliberator spamassassin
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION ${LIBDIR}/spmfilter
)
