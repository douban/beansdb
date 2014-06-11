bin_PROGRAMS = beansdb
beansdb_SOURCES = beansdb.c item.c fnv1a.h fnv1a.c beansdb.h thread.c htree.h htree.c hint.h hint.c record.h record.c codec.h codec.c bitcask.h bitcask.c hstore.h hstore.c quicklz.h quicklz.c diskmgr.h diskmgr.c util.h const.h log.h log.c
beansdb_CPPFLAGS = -DNDEBUG -I ../third-party/zlog-1.2/
beansdb_LDFLAGS = -L ../third-party/zlog-1.2/
LIBS += -lzlog

