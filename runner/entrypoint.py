import json, os, subprocess, threading, time, signal
os.chdir('/runner')
with open('bootstrap.json') as f:
    cfg=json.load(f)
os.unlink('bootstrap.json')
args=['./config.sh','--unattended','--ephemeral','--disableupdate','--url',cfg['url'],'--token',cfg['token'],'--name',cfg['name'],'--labels',cfg['labels'],'--work','_work']
if cfg.get('group'): args.extend(['--runnergroup',cfg['group']])
# Registration completes before workflow execution; the token is no longer retained.
subprocess.run(args,check=True)
del cfg, args
listener=subprocess.Popen(['./run.sh'])
def stop_after_detach():
    while listener.poll() is None:
        if os.path.exists('.detached'):
            listener.send_signal(signal.SIGINT)
            return
        time.sleep(1)
threading.Thread(target=stop_after_detach,daemon=True).start()
raise SystemExit(listener.wait())
