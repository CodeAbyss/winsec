@echo off
cl /nologo /O2 /c md5.c
cl /nologo /O2 /c sha1.c
cl /nologo /O2 /c sha256.c
cl /nologo /O2 /c vt.cpp
cl /nologo /O2 /c jsmn.c
link /nologo /subsystem:console vt.obj md5.obj sha1.obj sha256.obj jsmn.obj