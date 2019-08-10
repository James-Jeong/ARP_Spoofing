TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    mod_ARP.cpp \
    mod_Eth.cpp \
    mod_IP.cpp \
    mod_TCP.cpp \
    mod_UDP.cpp \
    Processing.cpp \
    Session.cpp

HEADERS += \
    stdafx.h \
    libnet-asn1.h \
    libnet-functions.h \
    libnet-headers.h \
    libnet-macros.h \
    libnet-structures.h \
    libnet-types.h \
    mod_UDP.h \
    mod_TCP.h \
    mod_IP.h \
    mod_Eth.h \
    mod_ARP.h \
    Processing.h \
    Session.h

LIBS += -lpcap
LIBS += -lpthread
