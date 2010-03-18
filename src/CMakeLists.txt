set(PLUGIN_SRC
	main.c
)

add_library(spamassassin SHARED ${PLUGIN_SRC})
target_link_libraries(spamassassin ${SPMFILTER_LIBRARIES} ${GLIB2_LIBRARIES})

install(TARGETS spamassassin
	RUNTIME DESTINATION bin
	LIBRARY DESTINATION lib/spmfilter
)
