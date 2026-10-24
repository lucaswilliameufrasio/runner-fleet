#!/usr/bin/env python3
"""Smoke test of a built server and its compiled SPA; uses disposable data."""
import argparse, base64, hashlib, http.cookiejar, json, re, secrets, subprocess, tempfile, time, urllib.request, urllib.error
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--server',default='dist/runner-fleet-server-linux-amd64');p.add_argument('--web',default='web/build');args=p.parse_args()
with tempfile.TemporaryDirectory() as data:
    binary=str(Path(args.server).resolve());web=str(Path(args.web).resolve())
    code=subprocess.check_output([binary,'setup-code','--data',data],text=True).strip()
    proc=subprocess.Popen([binary,'serve','--data',data,'--web',web,'--listen','127.0.0.1:8090','--origin','http://localhost:8090','--dev'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    try:
        opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        def req(path,method='GET',body=None,csrf='',origin=None):
            headers={'Content-Type':'application/json','X-CSRF-Token':csrf}
            if origin:headers['Origin']=origin
            r=urllib.request.Request('http://localhost:8090'+path,data=None if body is None else json.dumps(body).encode(),headers=headers,method=method)
            with opener.open(r,timeout=10) as res:return res.status,dict(res.headers),res.read()
        for _ in range(100):
            try:req('/api/health');break
            except Exception:time.sleep(.05)
        status,headers,html=req('/setup');assert status==200
        for script in re.findall(rb'<script[^>]*>(.*?)</script>',html,re.S):
            if script:
                digest=base64.b64encode(hashlib.sha256(script).digest()).decode()
                assert "'sha256-"+digest+"'" in headers.get('Content-Security-Policy','')
        for path in set(re.findall(rb'"(/_app/[^"\s]+\.js)"',html)):
            assert req(path.decode())[0]==200
        password=secrets.token_urlsafe(24)
        assert req('/api/auth/setup','POST',{'code':code,'email':'qa@fleet.test','password':password})[0]==201
        status,_,body=req('/api/auth/login','POST',{'email':'qa@fleet.test','password':password});assert status==200
        csrf=json.loads(body)['csrf']
        assert req('/api/state')[0]==200
        try:req('/api/enrollment','POST',{},'');raise AssertionError('missing CSRF accepted')
        except urllib.error.HTTPError as e:assert e.code==403
        assert req('/api/auth/reauth','POST',{'password':password},csrf)[0]==200
        status,_,body=req('/api/enrollment','POST',{},csrf);assert status==201 and len(json.loads(body)['code'])>32
        exported=json.loads(req('/api/export')[2]);assert 'private_key' not in exported
        assert req('/api/auth/logout','POST',{},csrf)[0]==200
        try:req('/api/state');raise AssertionError('logout session still active')
        except urllib.error.HTTPError as e:assert e.code==401
        print('HTTP artifact smoke passed: SPA assets/CSP, setup, login, CSRF, reauth, enrollment, export, logout.')
    finally:
        proc.terminate();proc.wait(timeout=10)
