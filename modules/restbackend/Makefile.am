AM_CPPFLAGS=@THREADFLAGS@ $(BOOST_CPPFLAGS)

EXTRA_DIST=OBJECTFILES OBJECTLIBS
lib_LTLIBRARIES = librestbackend.la

librestbackend_la_SOURCES=restbackend.cc restbackend.hh cJSON.c cJSON.h
librestbackend_la_LDFLAGS=-module -avoid-version

