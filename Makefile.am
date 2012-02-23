bin_PROGRAMS = beansdb
beansdb_SOURCES = beansdb.c item.c fnv1a.h beansdb.h thread.c htree.h htree.c hint.h hint.c record.h record.c codec.h codec.c bitcask.h bitcask.c hstore.h hstore.c quicklz.h quicklz.c diskmgr.h diskmgr.c
beansdb_CPPFLAGS = -DNDEBUG

SUBDIRS = doc
EXTRA_DIST = python crc32.c clock_gettime_stub.c ae_epoll.c ae_kqueue.c ae_select.c CREDITS AUTHORS LICENSE

dist-hook:
	rm -rf $(distdir)/*/.svn/
