#!/usr/bin/env python

import os
import sys
import ctypes

from defines import *
from errno   import *

libc = CDLL("libc.so.6")
_ptrace = libc.ptrace
_ptrace.argtypes = [c_uint, c_uint, c_long, c_long]
_ptrace.restype = c_long

class pyptrace:
    '''
    This class is a wrapper of ptrace 
    '''

    ####################################################################################################################
    def __init__(self):
        self.follow_forks   = False
        self.follow_execs   = False
        self.trace_sysgood  = False
        self.ptrace_options = 0

    ####################################################################################################################
    def get_errno(self):
        """
        Function get_errno(): get the current errno value.  This is a compatibility function for python <2.6

        Try different implementations adapted from python-ptrace:

         - __errno_location_sym symbol from the C library
         - PyErr_SetFromErrno() from the C Python API

        @raise An exception is raised on failure.
        @rtype Integer
        @return errno
        """

        #Try to get errno integer from libc using __errno_location_sym function.
        #
        #This function is specific to OS with "libc.so.6" and may fails for
        #thread-safe libc.
        try:
            __errno_location = libc.__errno_location_sym
            flag = True
        except AttributeError:
            # libc doesn't have __errno_location
            flag = False

        if flag:
            __errno_location.restype = POINTER(c_int)
            return __errno_location()[0]


        # Function from pypy project:
        # File pypy/dist/pypy/rpython/rctypes/aerrno.py
        #
        # Read errno using Python C API: raise an exception with PyErr_SetFromErrno
        # and then read error code 'errno'.
        #
        # This function may raise an RuntimeError.
        try:
            pythonapi.PyErr_SetFromErrno(py_object(OSError))
        except OSError, err:
            return err.errno
        else:
            raise RuntimeError("get_errno() is unable to get error code")

    ####################################################################################################################
    def ptrace(self, request, pid=0, address=0, data=0):
        '''
        Convenience wrapper around the ptrace syscall.

        @type  request: C Unsigned Integer
        @param request: Ptrace request type
        @type  pid: C Unsigned Integer
        @param pid: Process ID to attach to
        @type  addr: C Void Pointer
        @param addr: location
        @type  data: C Void Pointer
        @param data: data
        '''

        try:
            result = _ptrace(request, pid, address, data)
        except ArgumentError as err:
            print "Ptrace error: all arguments must be integers:"
            print " ptrace(%r, %r, %r, %r)" % (request,pid,address,data)
            print err
            exit()

        if result == -1:
            try:
                # if on python 2.6 then use ctypes get_errno()
                errno = ctypes.get_errno()
            except NameError:
                # if on python 2.5 then use internal get_errno() hack
                errno = self.get_errno()

            if errno != 0:
                message = "error: ptrace(request=%r, pid=%r, address=%x, data=%d)" % (request, pid, address, data)
                sys.stderr.write("%s\nerrno is %d (%s)\n" % (message,errno,os.strerror(errno)))
                exit()

        return result

    ####################################################################################################################
    def ptrace_attach(self, pid):
        '''
        Convenience wrapper around PTRACE_ATTACH

        Attaches  to the process specified in pid, making it a traced "child" of the calling process;
        the behavior of the child is as if it had done a PTRACE_TRACEME.  The calling  process  actu-
        ally becomes the parent of the child process for most purposes (e.g., it will receive notifi-
        cation of child events and appears in ps(1) output as the child\'s parent), but  a  getppid(2)
        by  the child will still return the PID of the original parent.  The child is sent a SIGSTOP,
        but will not necessarily have stopped by the completion of this call; use wait(2) to wait for
        the child to stop.  (addr and data are ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        '''

        return self.ptrace(PTRACE_ATTACH, pid, 0, 0)

    ####################################################################################################################
    def ptrace_cont(self, pid, data=0):
        '''
        Convenience wrapper around PTRACE_CONT

        Restarts  the  stopped child process.  If data is non-zero and not SIGSTOP, it is interpreted
        as a signal to be delivered to the child; otherwise, no signal is delivered.  Thus, for exam-
        ple, the parent can control whether a signal sent to the child is delivered or not.  (addr is
        ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Optional signal to be delivered to the child
        '''

        return self.ptrace(PTRACE_CONT, pid, 0, data)

    ####################################################################################################################
    def ptrace_detach(self, pid, data=0):
        '''
        Convenience wrapper around PTRACE_DETACH

        Restarts  the  stopped child as for PTRACE_CONT, but first detaches from the process, undoing
        the reparenting effect of PTRACE_ATTACH, and the effects of PTRACE_TRACEME.  Although perhaps
        not  intended,  under  Linux  a  traced child can be detached in this way regardless of which
        method was used to initiate tracing.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Optional signal to be delivered to the child
        '''

        return self.ptrace(PTRACE_DETACH, pid, 0, data)

    ####################################################################################################################
    def ptrace_geteventmsg(self, pid, data):
        '''
        Convenience wrapper around PTRACE_GETEVENTMSG

        Retrieve  a  message (as an unsigned long) about the ptrace event that just happened, placing
        it in the location data in the parent.  For PTRACE_EVENT_EXIT this is the child\'s  exit  sta-
        tus.  For PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK and PTRACE_EVENT_CLONE this is the PID of the
        new process.  Since Linux  2.6.18,  the  PID  of  the  new  process  is  also  available  for
        PTRACE_EVENT_VFORK_DONE.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to write to
        '''

        return self.ptrace(PTRACE_GETEVENTMSG, pid, 0, data)

    ####################################################################################################################
    def ptrace_getfpregs(self, pid, data):
        '''
        Convenience wrapper around PTRACE_GETFPREGS

        Copies  the  child\'s  floating-point registers to location data in the parent.
        See <linux/user.h> for information on the format of this data.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to write to
        '''

        return self.ptrace(PTRACE_GETFPREGS, pid, 0, data)

    ####################################################################################################################
    def ptrace_getregs(self, pid, data):
        '''
        Convenience wrapper around PTRACE_GETREGS

        Copies the child\'s general purpose registers to location data in the parent.  
        See <linux/user.h> for information on the format of this data.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to write to
        '''

        return self.ptrace(PTRACE_GETREGS, pid, 0, data)

    ####################################################################################################################
    def ptrace_getsiginfo(self, pid, data):
        '''
        Convenience wrapper around PTRACE_GETSIGINFO

        Retrieve  information  about  the  signal that caused the stop.  Copies a siginfo_t structure
        (see sigaction(2)) from the child to location data in the parent.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to write to
        '''

        return self.ptrace(PTRACE_GETSIGINFO, pid, 0, data)

    ####################################################################################################################
    def ptrace_kill(self, pid):
        '''
        Convenience wrapper around PTRACE_KILL

        Sends the child a SIGKILL to terminate it.  (addr and data are ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        '''

        return self.ptrace(PTRACE_KILL, pid, 0, 0)

    ####################################################################################################################
    def ptrace_options(self):
        '''
        Ptrace options (PTRACE_SETOPTIONS). 
        '''

        if self.follow_forks:
            self.ptrace_options |= PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK

        if self.follow_execs:
            self.ptrace_options |= PTRACE_O_TRACEEXEC

        if self.trace_sysgood:
            """
            Enable sysgood option: ask the kernel to set bit #7 of the signal
            number if the signal comes from the kernel space. If the signal comes
            from the user space, the bit is unset.
            """
            self.ptrace_options |= PTRACE_O_TRACESYSGOOD

    ####################################################################################################################
    def ptrace_peekdata(self, pid, addr):
        '''
        Convenience wrapper around PTRACE_PEEKDATA

        Reads  a word at the location addr in the child\'s memory, returning the word as the result of
        the ptrace() call.  Linux does not have separate text and data address  spaces,  so  the  two
        requests are currently equivalent.  (The argument data is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory
        '''

        return self.ptrace(PTRACE_PEEKDATA, pid, addr, 0)

    ####################################################################################################################
    def ptrace_peektext(self, pid, addr):
        '''
        Convenience wrapper around PTRACE_PEEKTEXT

        Reads  a word at the location addr in the child\'s memory, returning the word as the result of
        the ptrace() call.  Linux does not have separate text and data address  spaces,  so  the  two
        requests are currently equivalent.  (The argument data is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory
        '''

        return self.ptrace(PTRACE_PEEKTEXT, pid, addr, 0)

    ####################################################################################################################
    def ptrace_peekuser(self, pid, addr):
        '''
        Convenience wrapper around PTRACE_PEEKUSER

        Reads  a  word  at  offset addr in the child\'s USER area, which holds the registers and other
        information about the process (see <linux/user.h> and <sys/user.h>).  The word is returned as
        the  result  of  the  ptrace()  call.  Typically the offset must be word-aligned, though this
        might vary by architecture.  (data is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory.  Must be aligned.
        '''

        if addr % CPU_WORD_SIZE:
            sys.stderr.write("ptrace_peekuser can't read a word from an unaligned address (%s)!" % addr)
            return

        return self.ptrace(PTRACE_PEEKUSER, pid, addr, 0)

    ####################################################################################################################
    def ptrace_pokedata(self, pid, addr, data):
        '''
        Convenience wrapper around PTRACE_POKEDATA

        Copies the word data to location addr in the child\'s memory.

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory
        @type  data: Integer
        @param data: Data to write in the child's data area.
        '''

        return self.ptrace(PTRACE_POKEDATA, pid, addr, data)

    ####################################################################################################################
    def ptrace_poketext(self, pid, addr, data):
        '''
        Convenience wrapper around PTRACE_POKETEXT

        Copies the word data to location addr in the child\'s memory.

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory
        @type  data: Integer
        @param data: Data to write in the child's text area.
        '''

        return self.ptrace(PTRACE_POKETEXT, pid, addr, data)

    ####################################################################################################################
    def ptrace_pokeuser(self, pid, addr, data):
        '''
        Convenience wrapper around PTRACE_POKEUSER

        Copies the word data to offset addr in the child\'s USER area.  As above, the offset must typically be
        word-aligned.  In order to maintain the integrity of the kernel, some modifications to the USER  area
        are disallowed.

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  addr: Integer
        @param addr: Location in the child's memory.  Must be aligned.
        @type  data: Integer
        @param data: Data to write in the child's USER area.
        '''

        if addr % CPU_WORD_SIZE:
            sys.stderr.write("ptrace_pokeuser can't write a word to an unaligned address (%s)!" % addr)
            return

        return self.ptrace(PTRACE_POKEUSER, pid, addr, data)

    ####################################################################################################################
    def ptrace_setfpregs(self, pid, data):
        '''
        Convenience wrapper around PTRACE_SETFPREGS

        Copies the child\'s floating-point registers from  location data  in the parent.  
        As for PTRACE_POKEUSER, some general purpose register modifications may be disallowed.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to copy from
        '''

        return self.ptrace(PTRACE_SETFPREGS, pid, 0, data)

    ####################################################################################################################
    def ptrace_setoptions(self, pid, data):
        '''
        Convenience wrapper around PTRACE_SETOPTIONS

        Sets  ptrace options from data in the parent.  (addr is ignored.)  data is interpreted as a
        bit mask of options.

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Ptrace options bitmask
        '''

        return self.ptrace(PTRACE_SETOPTIONS, pid, 0, data)

    ####################################################################################################################
    def ptrace_setregs(self, pid, data):
        '''
        Convenience wrapper around PTRACE_SETREGS

        Copies the child\'s general purpose registers from location data in the parent.  
        As for PTRACE_POKEUSER, some general purpose register modifications may be disallowed.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to copy from
        '''

        return self.ptrace(PTRACE_SETREGS, pid, 0, data)

    ####################################################################################################################
    def ptrace_setsiginfo(self, pid, data):
        '''
        Convenience wrapper around PTRACE_SETSIGINFO

        Set signal information.  Copies a siginfo_t structure from location data in the parent to the
        child.   This will only affect signals that would normally be delivered to the child and were
        caught by the tracer.  It may be difficult to tell these normal signals from  synthetic  sig-
        nals generated by ptrace() itself.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Location in the parent to write to
        '''

        return self.ptrace(PTRACE_SETSIGINFO, pid, 0, data)

    ####################################################################################################################
    def ptrace_singlestep(self, pid):
        '''
        Convenience wrapper around PTRACE_SINGLESTEP

        Restarts the stopped child as for PTRACE_CONT, but arranges for the child to be stopped
        after execution of a single instruction.  (The child will also, as usual, be stopped upon receipt of a signal.)
        From the parent\'s perspective, the child will appear to have been stopped by receipt of a SIGTRAP.

        @type  pid: Integer
        @param pid: Process ID to attach to
        '''

        return self.ptrace(PTRACE_SINGLESTEP, pid, 0, 0)

    ####################################################################################################################
    def ptrace_syscall(self, pid, data=0):
        '''
        Convenience wrapper around PTRACE_SYSCALL

        Restarts the stopped child as for PTRACE_CONT, but arranges for the child to  be  stopped  at
        the  next  entry  to  or exit from a system call.  (The child will also, as usual, be stopped
        upon receipt of  a  signal.)   From the parent\'s perspective, the child will appear to have
        been stopped by receipt of a SIGTRAP.

        So, for PTRACE_SYSCALL, for example, the idea is to inspect the arguments to the system  call
        at  the first stop, then do another PTRACE_SYSCALL and inspect the return value of the system
        call at the second stop.  (addr is ignored.)

        @type  pid: Integer
        @param pid: Process ID to attach to
        @type  data: Integer
        @param data: Optional signal
        '''

        return self.ptrace(PTRACE_SYSCALL, pid, 0, data)

    ####################################################################################################################
    def ptrace_traceme(self):
        '''
        Convenience wrapper around PTRACE_TRACEME

        Indicates that this process is to be traced by  its  parent.   Any  signal  (except  SIGKILL)
        delivered  to  this  process will cause it to stop and its parent to be notified via wait(2).
        Also, all subsequent calls to execve(2) by this process will cause a SIGTRAP to  be  sent  to
        it,  giving  the  parent a chance to gain control before the new program begins execution.  A
        process probably shouldn\'t make this request if its  parent  isn\'t  expecting  to  trace  it.
        (pid, addr, and data are ignored.)
        '''

        return self.ptrace(PTRACE_TRACEME, 0, 0, 0)

    ####################################################################################################################
    def wait(self):
        '''
        Convenience wrapper around wait()
        '''

        try:
            pid, exit_status = os.wait()
        except OSError, detail:
            sys.stderr.write("%s,%d,%d" % (detail, detail.errno, pid))
            exit()

        return pid, exit_status

    ####################################################################################################################
    def waitpid(self, pid=-1, ptrace_options=None):
        '''
        Convenience wrapper around waitpid()

        @type  pid: Integer
        @param pid: Process ID to wait for status from
        '''

        try:
            if ptrace_options == None:
                pid, exit_status = os.waitpid(pid, self.ptrace_options)
            else:
                pid, exit_status = os.waitpid(pid, ptrace_options)
        except OSError, detail:
            sys.stderr.write("%s,%d,%d" % (detail, detail.errno, pid))
            exit()

        return pid, exit_status
