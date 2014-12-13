all:
	ar rvs libbeansdb.a  ../src/beansdb-hstore.o ../src/beansdb-quicklz.o ../src/beansdb-bitcask.o ../src/beansdb-htree.o   ../src/beansdb-record.o ../src/beansdb-codec.o   ../src/beansdb-item.o    ../src/beansdb-thread.o ../src/beansdb-diskmgr.o ../src/beansdb-log.o ../src/beansdb-hint.o ../src/beansdb-mfile.o ../src/beansdb-common.o
	go fmt *.go

test:
	go test

clean:
	go clean
