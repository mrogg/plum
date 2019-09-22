"""Contains code to support daemonization of a process

References:
    * http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/278731 
    * http://homepage.hispeed.ch/py430/python/daemon.py
    * http://aspn.activestate.com/ASPN/Cookbook/Python/Recipe/66012
    * http://blog.doughellmann.com/2007/06/pymotw-os-part-4.html
"""
import os
import sys

def getevil():
    """Daemonize this process"""
    
    try:    
        # Creates a clone child process
        # Returns the pid of the child process to the master/original
        # process and 0 to the child process. So, pid = 0 in the child
        # process.
        pid = os.fork()
    except OSError, e:
        sys.stderr.write("Fork #1 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)
        
    # So if pid is not 0 (so, only master process will run this)
    # then exit without calling cleanup handlers, flushing stdio 
    # buffers, etc. (os._exit not sys.exit)
    if pid:
        os._exit(0)

    # Now, we're just left with the new child process.
    # It's parent process is 1 (init on linux, launchd on os-x) now.
    # Now create a new session nad make our new process the session
    # leader and the process group leader, it will have no controlling
    # terminal.
    os.setsid()

    try:
        # Fork off again. 
        # Prevents new process from acquiring a controlling terminal. Not sure
        # I really understand the need for this second fork yet.
        pid = os.fork()
    except OSError, e:
        sys.stderr.write("Fork #2 failed: (%d) %s\n" % (e.errno, e.strerror))
        sys.exit(1)

    # Same as above, get rid of the first child now
    if pid:
        os._exit(0)

    # Now we're in the second child process. 
    # We'll change the directory to / to avoid making and filesystem
    # un-umount-able
    os.chdir('/')

    # Reset file creation mask so it's not inherited from the parent
    os.umask(0)

    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    os.close(sys.stdin.fileno())
    os.close(sys.stdout.fileno())
    os.close(sys.stderr.fileno())
    si = file('/dev/null', 'r')
    so = file('/dev/null', 'a+')
    se = file('/dev/null', 'a+', 0)
    os.dup2(si.fileno(), sys.stdin.fileno())
    os.dup2(so.fileno(), sys.stdout.fileno())
    os.dup2(se.fileno(), sys.stderr.fileno())


if __name__ == '__main__':
    getevil()

