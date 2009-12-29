bin_PROGRAMS = beansdb
beansdb_SOURCES = beansdb.c item.c fnv1a.h beansdb.h thread.c htree.h htree.c stats.c hstore.h hstore.c

SUBDIRS = doc tools
EXTRA_DIST = python CREDITS AUTHORS LICENSE

dist-hook:
	rm -rf $(distdir)/*/.svn/
