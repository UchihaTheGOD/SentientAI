"""Security Test Lab runner — executes lab tests via TestClient.

Canonical helpers (validate_target_url, CANARYForType, _synthetic_evidence,
_TEST_LOCK) live in app/services/security_lab.py and are re-exported here
so existing imports keep working without duplication.
"""
from __future__ import annotations

import json as _json
import re
import time as _time
import uuid as _uuid
import urllib.parse as _up
from datetime import datetime as _dt
from datetime import timezone as _tz

from app.models.security_lab import SecurityLabRun as _Run
from app.services.security_lab import (  # canonical — no duplication
    CANARYForType as _cf,
)
from app.services.security_lab import _TEST_LOCK as _LK
from app.services.security_lab import _TEST_TYPES as _TT
from app.services.security_lab import _local_origin as _lo
from app.services.security_lab import _synthetic_evidence as _se
from app.services.security_lab import validate_target_url as _vt

# Re-export canonical helpers so `from security_lab_runner import ...` works.
from app.services.security_lab import CANARYForType  # noqa: F401
from app.services.security_lab import _TEST_LOCK  # noqa: F401
from app.services.security_lab import _TEST_TYPES  # noqa: F401
from app.services.security_lab import _allowlist, _local_origin, _synthetic_evidence, validate_target_url  # noqa: F401

lab_run_lock = _LK


def run_lab_test(db, *, test_type, target_url, custom_string, created_by, request=None):
    if test_type not in _TT: raise ValueError('unknown '+test_type)
    if test_type=='custom':
        if not custom_string or not custom_string.strip(): raise ValueError('custom requires string <=300')
        if len(custom_string.strip())>300: raise ValueError('custom too long')
    is_synth=test_type in ('port_scan','bruteforce')
    if is_synth:
        if target_url:
            n,e=_vt(target_url)
            if e: raise ValueError(e)
            target=n
        else: target=_lo()
    else:
        if not target_url:
            if test_type in ('xss','sqli','traversal','custom'): target_url=_lo().rstrip('/')+'/search?q='+_up.quote((custom_string or _cf(test_type))[:80])
            elif test_type=='login_fail': target_url=_lo().rstrip('/')+'/login'
            else: target_url=_lo()
        n,e=_vt(target_url)
        if e: raise ValueError(e)
        target=n
    if not _LK.acquire(blocking=False): raise ValueError('another test is already running')
    t0=_time.perf_counter(); start=_dt.now(_tz.utc).isoformat()
    # Attribution window: only events created during THIS test run may
    # count toward its detection. The old code used "last 900 seconds",
    # so any other user's failed login or suspicious request within
    # 15 minutes made an unrelated test report "detected", and the
    # first-30 cap could hide the test's own events. Correlation ids
    # cannot fix this: the middleware assigns its own per-request id
    # and never reads a client-sent header, so the runner's ids are
    # never attached to the events its requests generate.
    started_dt=_dt.now(_tz.utc)
    cids=[]; eids=[]; sts=[]; req=0; resp=0; det='not_detected'; err=None
    meta={'test_type':test_type,'start':start,'is_synthetic':is_synth}
    try:
        if is_synth:
            from app.services.security_events import log_event as _log
            ev=_se(test_type, custom_string); cid=_uuid.uuid4().hex[:16]; cids.append(cid)
            row=_log(db, event_type='lab.synthetic.'+test_type, category=test_type, severity='info', confidence='low', source='lab', route=target, evidence=ev, meta={'synthetic':True,'test_type':test_type,'target':target}, correlation_id=cid)
            eids.append(row.id); meta['synthetic_evidence']=ev[:500]; det='synthetic'
        else:
            from app.main import create_app
            from starlette.testclient import TestClient
            app=create_app(); cl=TestClient(app, raise_server_exceptions=False); cl.get('/'); csrf=cl.cookies.get('csrf_token','') or ''
            def _do(m, pth, data=None):
                nonlocal req, resp
                req+=1; cids.append(_uuid.uuid4().hex[:16])
                try:
                    if m=='GET': r=cl.get(pth)
                    elif m=='POST': r=cl.post(pth, data=data or {}, headers={'X-CSRF-Token': csrf} if csrf else {})
                    else: r=cl.request(m, pth)
                    sts.append(r.status_code); resp+=1; return r
                except Exception: sts.append(0); return None
            if test_type=='xss': _do('GET','/search?q='+_up.quote('ATTACT-XSS-CANARY-9f3a1b<script>alert(1)</script>'))
            elif test_type=='sqli': _do('GET','/search?q='+_up.quote(chr(39)+chr(34)+' ATTACT'))
            elif test_type=='traversal': _do('GET','/static/../../etc/passwd')
            elif test_type=='login_fail':
                import re; cnt=3
                if custom_string and 'count=' in custom_string:
                    try:
                        mm=re.search(r'count\s*=\s*(\d+)', custom_string)
                        if mm: cnt=min(6,max(1,int(mm.group(1))))
                    except Exception: pass
                meta['login_attempts']=cnt
                for ii in range(cnt): _do('POST','/login', data={'username':'lab_no_user_'+str(ii),'password':'Wrong12345!'})
            elif test_type=='custom':
                qv=(custom_string or '')[:120]; pp=_up.urlparse(target); bp=pp.path or '/search'
                if bp in ('/',''): bp='/search'
                pth=None
                if bp.startswith('/search'): pth='/search?q='+_up.quote(qv)
                elif bp=='/login': _do('POST','/login', data={'username':'lab_custom','password':qv[:40]})
                else: pth=target.replace(_lo().rstrip('/'),'') or '/search?q='+_up.quote(qv)
                if pth is not None: _do('GET', pth)
            try:
                from app.models.attact_assessment import SecurityEvent
                from app.database import SessionLocal as _SL
                _sdb=_SL()
                rows=_sdb.query(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(500).all()
                # Only events from this test's own window count, and
                # detection looks at ALL of them: capping first and
                # then testing could hide the test's own events.
                seen=[]
                for _r in rows:
                    _ca=getattr(_r,'created_at',None)
                    if _ca is None: continue
                    try:
                        if _ca.tzinfo is None: _ca=_ca.replace(tzinfo=_tz.utc)
                        if _ca >= started_dt: seen.append(_r)
                    except Exception: continue
                for r in seen: eids.append(r.id)
                has=any((r.event_type or '').startswith('suspicious_input') or (r.event_type or '')=='auth.login_failed' or (r.event_type or '').startswith('http.') for r in seen)
                det='detected' if has else 'not_detected'; meta['events_window']=len(seen); meta['events_attribution']='time_window'
                _sdb.close()
            except Exception as e: meta['event_scan_error']=str(e)[:300]
    except ValueError: raise
    except Exception as e: err=str(e)[:800]; det='error'; meta['exception']=type(e).__name__
    finally:
        try: _LK.release()
        except Exception: pass
    comp=_dt.now(_tz.utc); meta['completed']=comp.isoformat(); meta['elapsed_ms']=int((_time.perf_counter()-t0)*1000)
    meta['target_normalized']=target if 'target' in locals() else (target_url or '')
    run=_Run(created_by=created_by, test_type=test_type, target_url=meta['target_normalized'], is_synthetic=is_synth, status='completed' if not err else 'failed', correlation_ids=_json.dumps(cids, ensure_ascii=False), event_ids=_json.dumps(eids, ensure_ascii=False), request_count=req, response_count=resp, http_statuses=_json.dumps(sts, ensure_ascii=False), detection_result=det, error_message=err, meta_json=_json.dumps(meta, ensure_ascii=False), completed_at=comp)
    db.add(run); db.commit(); db.refresh(run)
    return run
