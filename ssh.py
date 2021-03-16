#!/usr/bin/python3

import os
import psutil
from lib.mfa import mfa

# 0. Get sshd pid (parent pid) and then remote IP from that
# 1. check for existing approved connection
# 2. request new approved connection if not found
# 3. check for approval
# 4. sleep 10
# 5. goto 3
# 6. timeout after 60 seconds?
# 7. if approved, return list of keys
# 8. otherwise, return empty list/exit 1

#mfa = mfa()

p_sshd = psutil.Process(os.getppid())
if p_sshd.exe() != "/usr/bin/sshd":
    sys.stderr.write("Parent process is not sshd\n")
    sys.exit(1)
