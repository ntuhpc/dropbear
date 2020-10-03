#!/usr/bin/env python

"""
This program opens a listening socket on the local machine, then spawns
individual instances of dropbear to service incoming connections, just like
inetd (albeit an extremely insecure version).

Compatible with both Python2 and Python3 (to be independent of whatever
version of Python was bundled in a container image).

Of course this is not implemented in an extremely secure way - the main
purpose of this is to locate open ports on hosts to spawn SSH servers on
to wire up HPC containers that have difficulties running in the more
"modern" hybrid mode.
"""

from __future__ import print_function
import os
import sys
import subprocess
import socket


def print_stderr(*args, **kwargs):
    kwargs["file"] = sys.stderr
    return print(*args, **kwargs)


def main():
    portfile = os.environ.get("NTUHPC_DROPBEAR_AUTOPORT_PORTFILE", "")
    try:
        executable = os.environ["NTUHPC_DROPBEAR_AUTOPORT_DROPBEAR_EXECUTABLE"]
    except KeyError:
        print_stderr("error: must provide path to dropbear executable")
        return 0

    print_stderr("info: writing port to:", portfile)
    print_stderr("info: dropbear executable:", executable)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("", 0))
    allocated = sock.getsockname()[1]
    print_stderr("info: allocated port:", allocated)

    sock.listen()
    print_stderr("info: listening for connections")

    if portfile != "":
        try:
            with open(portfile, "w") as f:
                f.write(str(allocated)+"\n")
        except Exception:
            print_stderr("error: could not write port to portfile")
            raise

    while True:
        sock_client, addr = sock.accept()
        fd = sock_client.fileno()
        print_stderr("info: client connected from:", addr, "on fd", fd)

        try:
            subprocess.Popen(
                executable, shell=False, stdin=fd, stdout=fd, close_fds=True
            )
        except Exception:
            print_stderr("error: cannot execute child dropbear executable")
            raise

        print_stderr("info: forked off dropbear")
        sock_client.close()


if __name__ == "__main__":
    main()
