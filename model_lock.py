"""One bounded inference slot shared by every provider and caller."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import tempfile
import time


@contextmanager
def inference_slot(timeout=5):
    folder=Path(tempfile.gettempdir())/('soc-model-'+str(os.getuid()))
    folder.mkdir(mode=0o700,exist_ok=True)
    info=folder.lstat()
    if folder.is_symlink() or info.st_uid!=os.getuid() or info.st_mode&0o077:
        raise ValueError('Unsafe model lock directory')
    deadline=time.monotonic()+timeout
    with (folder/'inference.lock').open('a') as lock:
        while True:
            try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB);break
            except BlockingIOError:
                if time.monotonic()>=deadline:raise TimeoutError('Model slot busy; no parallel request or automatic retry') from None
                time.sleep(0.05)
        try:yield
        finally:fcntl.flock(lock,fcntl.LOCK_UN)
