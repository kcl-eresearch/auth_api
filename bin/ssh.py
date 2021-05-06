#!/usr/bin/python3

import os
import psutil
import sys
import syslog

def log_error(message):
    syslog.syslog(syslog.LOG_ERR, message)
    sys.stderr.write(f"{message}\n")

def log_info(message):
    syslog.syslog(syslog.LOG_INFO, message)
    print(message)

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

ppid = os.getppid()
p_sshd = psutil.Process(ppid)
if p_sshd.exe() != "/usr/sbin/sshd":
    log_error("Parent process is not sshd\n")
    sys.exit(1)

remote_ip = None
for conn in psutil.net_connections(kind="tcp"):
    if conn.laddr[1] == 22 and conn.status == psutil.CONN_ESTABLISHED:
        if conn.pid == ppid:
            remote_ip = conn.raddr[0]
            break
        proc = psutil.Process(conn.pid)
        if proc.ppid() == ppid:
            remote_ip = conn.raddr[0]
            break

if not remote_ip:
    log_error("Cannot determine remote IP address")
    sys.exit(1)

log_info(remote_ip)
