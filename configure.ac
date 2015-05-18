AC_PREREQ(2.61)
AC_INIT([beansdb], [0.7.1.4], [davies.liu@gmail.com])
AM_INIT_AUTOMAKE([-Wall -Werror foreign subdir-objects])
AC_PROG_CC
AM_PROG_CC_C_O
AC_CONFIG_HEADERS([config.h])


AC_SEARCH_LIBS(socket, socket)
AC_SEARCH_LIBS(gethostbyname, nsl)
AC_SEARCH_LIBS(mallinfo, malloc)
AC_SEARCH_LIBS(pthread_create, pthread)

AC_CHECK_LIB([rt], [clock_gettime])
AC_CHECK_FUNC(daemon,AC_DEFINE([HAVE_DAEMON],,[Define this if you have daemon()]),[AC_LIBOBJ(daemon)])
AC_CHECK_HEADER([sys/epoll.h], AC_DEFINE([HAVE_EPOLL], , [for epoll support])) 
AC_CHECK_HEADER([sys/event.h], AC_DEFINE([HAVE_KQUEUE], , [for kqueue support])) 

AC_HEADER_STDBOOL
AC_C_CONST
AC_CHECK_HEADER(malloc.h, AC_DEFINE(HAVE_MALLOC_H,,[do we have malloc.h?]))
AC_CHECK_MEMBER([struct mallinfo.arena], [
        AC_DEFINE(HAVE_STRUCT_MALLINFO,,[do we have stuct mallinfo?])
    ], ,[
#    include <malloc.h>
    ]
)

dnl From licq: Copyright (c) 2000 Dirk Mueller
dnl Check if the type socklen_t is defined anywhere
AC_DEFUN([AC_C_SOCKLEN_T],
[AC_CACHE_CHECK(for socklen_t, ac_cv_c_socklen_t,
[
  AC_TRY_COMPILE([
    #include <sys/types.h>
    #include <sys/socket.h>
  ],[
    socklen_t foo;
  ],[
    ac_cv_c_socklen_t=yes
  ],[
    ac_cv_c_socklen_t=no
  ])
])
if test $ac_cv_c_socklen_t = no; then
  AC_DEFINE(socklen_t, int, [define to int if socklen_t not available])
fi
])

AC_C_SOCKLEN_T

AC_CONFIG_SUBDIRS([third-party/zlog-1.2])
AC_CONFIG_FILES([Makefile doc/Makefile src/Makefile])
AC_OUTPUT
