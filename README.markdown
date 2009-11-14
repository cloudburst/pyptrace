# pyptrace

[`pyptrace`] is a simple Python wrapper for Linux's ptrace.

## Usage:

git clone git://github.com/cloudburst/pyptrace.git

    >>> from pyptrace import *
    >>> dbg = pyptrace()
    >>> dbg.ptrace_attach(pid)
    >>> dbg.ptrace_detach(pid)
