bin_PROGRAMS = beansdb
#export JEMALLOC_PATH=${HOME}/local/jemalloc-3.6.0
beansdb_SOURCES = beansdb.c item.c fnv1a.h  beansdb.h thread.c htree.h htree.c hint.h hint.c record.h record.c codec.h codec.c bitcask.h bitcask.c hstore.h hstore.c quicklz.h quicklz.c diskmgr.h diskmgr.c util.h const.h log.h log.c mfile.h mfile.c
beansdb_CPPFLAGS = -I ../third-party/zlog-1.2/ # -I${JEMALLOC_PATH}/include
beansdb_LDFLAGS =  -L ../third-party/zlog-1.2/ # -L ${JEMALLOC_PATH}/lib -Wl,-rpath,${JEMALLOC_PATH}/lib
LIBS += -lzlog # -ljemalloc

