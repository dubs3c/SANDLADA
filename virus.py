#!/usr/bin/env python2

import os, sys

def forkSuccessful():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    os.setsid()
    os.umask(0)
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)
    except OSError:
        return 0
    return 1


def iseSURJTiXTid(duLZajeLU):
    try:
        os.kill(duLZajeLU, 0)
    except OSError:
        return
    else:
        return duLZajeLU

def writePID(pidFilePath):
    if os.path.exists(pidFilePath):
        try:
            if iseSURJTiXTid(int(open(pidFilePath).read())):
                os.kill(os.getpid(),9)
            else:
                os.remove(pidFilePath)
        except:
            try:
                os.remove(pidFilePath)
            except:
                pass
    open(pidFilePath, 'w').write(str(os.getpid()))
    return pidFilePath


if forkSuccessful():
    writePID(".pidw")
    print("Hello from FORK!")