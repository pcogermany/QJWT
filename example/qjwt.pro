QT += core
QT -= gui

CONFIG += c++11
CONFIG   -= flat

TARGET = test
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

LIBS += -lcrypto -lssl

include(../qjwt.pri)

SOURCES  += main.cpp
