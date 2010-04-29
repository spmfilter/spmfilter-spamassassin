set(MAN_SRC
	spmfilter-spamassassin.1
	smf-spamq.1
	smf-spamctl.1)

foreach(man ${MAN_SRC})
	create_manpage(${man})
endforeach(man)

