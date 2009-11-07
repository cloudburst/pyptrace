from ctypes import *
from os import uname


# ptrace linux defines from /usr/include/sys/ptrace.h


#   Indicate that the process making this request should be traced.
#     All signals received by this process can be intercepted by its
#     parent, and its parent can use the other `ptrace' requests.  
PTRACE_TRACEME = 0 
#   Return the word in the process's text space at address ADDR.  
PTRACE_PEEKTEXT = 1 
#   Return the word in the process's data space at address ADDR.  
PTRACE_PEEKDATA = 2 
#   Return the word in the process's user area at offset ADDR.  
PTRACE_PEEKUSER = 3 
#   Write the word DATA into the process's text space at address ADDR.  
PTRACE_POKETEXT = 4 
#   Write the word DATA into the process's data space at address ADDR.  
PTRACE_POKEDATA = 5 
#   Write the word DATA into the process's user area at offset ADDR.  
PTRACE_POKEUSER = 6 
#   Continue the process.  
PTRACE_CONT = 7 
#   Kill the process.  
PTRACE_KILL = 8 
#   Single step the process.
#     This is not supported on all machines.  
PTRACE_SINGLESTEP = 9
#  Get all general purpose registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETREGS = 12
#   Set all general purpose registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETREGS = 13
#   Get all floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETFPREGS = 14
#   Set all floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETFPREGS = 15
#   Attach to a process that is already running. 
PTRACE_ATTACH = 16
#   Detach from a process attached to with PTRACE_ATTACH.  
PTRACE_DETACH = 17
#   Get all extended floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_GETFPXREGS = 18
#   Set all extended floating point registers used by a processes.
#     This is not supported on all machines.  
PTRACE_SETFPXREGS = 19
#   Continue and stop at the next (return from) syscall.  
PTRACE_SYSCALL = 24


#   Set ptrace filter options.  
PTRACE_SETOPTIONS  = 0x4200
#   Get last ptrace message.  
PTRACE_GETEVENTMSG = 0x4201
#   Get siginfo for process.  
PTRACE_GETSIGINFO  = 0x4202
#   Set new siginfo for process.  
PTRACE_SETSIGINFO  = 0x4203


#  Options set using PTRACE_SETOPTIONS.
PTRACE_O_TRACESYSGOOD   = 0x00000001
PTRACE_O_TRACEFORK      = 0x00000002
PTRACE_O_TRACEVFORK     = 0x00000004
PTRACE_O_TRACECLONE     = 0x00000008
PTRACE_O_TRACEEXEC      = 0x00000010
PTRACE_O_TRACEVFORKDONE = 0x00000020
PTRACE_O_TRACEEXIT      = 0x00000040
PTRACE_O_MASK           = 0x0000007f


#  Wait extended result codes for the above trace options.
PTRACE_EVENT_FORK       = 1
PTRACE_EVENT_VFORK      = 2
PTRACE_EVENT_CLONE      = 3
PTRACE_EVENT_EXEC       = 4
PTRACE_EVENT_VFORK_DONE = 5
PTRACE_EVENT_EXIT       = 6 

_machine = uname()[4]
if _machine == "x86_64":
    CPU_WORD_SIZE = 8
elif _machine in ("i386", "i686"):
    CPU_WORD_SIZE = 4
