from __future__ import annotations
import json, os, socket, subprocess, time
from pathlib import Path
from typing import Any

SOCKET_PATH=os.environ.get('PRIVANET_CHAT_ADMIN_SHELL_SOCKET','/run/privanet-chat-shell/shell.sock')
WORK_DIR=os.environ.get('PRIVANET_CHAT_ADMIN_SHELL_WORK','/var/lib/privanet-chat-shell/work')
HOME=os.environ.get('PRIVANET_CHAT_ADMIN_SHELL_HOME','/var/lib/privanet-chat-shell')
PATH=os.environ.get('PRIVANET_CHAT_ADMIN_COMMAND_PATH','/opt/node/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin')
MAX_REQUEST=16*1024
MAX_OUTPUT=40000


def handle(req: dict[str,Any]) -> dict[str,Any]:
    if req.get('action')!='run': raise ValueError('unsupported shell action')
    cmd=str(req.get('command','')).strip()
    if not cmd or len(cmd)>8000 or '\x00' in cmd: raise ValueError('invalid command')
    timeout=max(1,min(int(req.get('timeout_seconds',20)),60))
    Path(WORK_DIR).mkdir(parents=True,exist_ok=True)
    started=time.monotonic()
    proc=subprocess.run(
        ['/bin/bash','--noprofile','--norc','-lc',cmd],
        cwd=WORK_DIR,text=True,capture_output=True,timeout=timeout,check=False,
        env={'PATH':PATH,'LANG':'C.UTF-8','HOME':HOME,'TMPDIR':'/tmp'},
    )
    return {'ok':proc.returncode==0,'exitCode':proc.returncode,'durationSeconds':round(time.monotonic()-started,3),'stdout':proc.stdout[-MAX_OUTPUT:],'stderr':proc.stderr[-20000:]}


def serve(conn: socket.socket):
    data=b''
    while b'\n' not in data and len(data)<=MAX_REQUEST:
        c=conn.recv(65536)
        if not c: break
        data+=c
    try:
        if len(data)>MAX_REQUEST: raise ValueError('request too large')
        req=json.loads(data.split(b'\n',1)[0].decode())
        result=handle(req)
        response={'ok':True,'result':result}
    except subprocess.TimeoutExpired as exc:
        response={'ok':True,'result':{'ok':False,'exitCode':124,'durationSeconds':float(exc.timeout or 0),'stdout':'','stderr':'command timed out'}}
    except Exception as exc:
        response={'ok':False,'error':{'code':'SHELL_REQUEST_FAILED','message':str(exc)[:300]}}
    conn.sendall((json.dumps(response,separators=(',',':'))+'\n').encode())


def main():
    p=Path(SOCKET_PATH); p.parent.mkdir(parents=True,exist_ok=True)
    if p.exists() or p.is_socket(): p.unlink()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.bind(str(p)); os.chmod(p,0o660); s.listen(16)
        while True:
            c,_=s.accept()
            with c: serve(c)

if __name__=='__main__': main()
