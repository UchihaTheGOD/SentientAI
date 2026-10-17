(function(){
  var btnRefresh=document.getElementById('lab-refresh-runs');
  if(btnRefresh) btnRefresh.addEventListener('click', refreshLabRuns);
  var sel=document.getElementById('lab-test-type');
  if(sel) sel.addEventListener('change', function(e){
    var v=e.target.value; var t=document.getElementById('lab-target');
    if(v==='login_fail') t.value='http://127.0.0.1:8000/login';
    else if(v==='port_scan'||v==='bruteforce') t.value='http://127.0.0.1:8000/';
    else t.value='http://127.0.0.1:8000/search';
  });
  window._lastLabId=null;
  var labForm=document.getElementById('lab-form');
  if(labForm) labForm.addEventListener('submit', async function(e){
    e.preventDefault();
    var fd=new FormData(e.target);
    var body={ test_type: fd.get('test_type'), target_url: (fd.get('target_url')||'').trim()||undefined, custom_string: (fd.get('custom_string')||'').trim()||undefined };
    var btn=document.getElementById('lab-run-btn'); btn.disabled=true;
    document.getElementById('lab-status').textContent='Running...';
    document.getElementById('lab-result').textContent='Running test...';
    try{
      var r=await fetch('/api/security/lab/run',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token': labCsrf()},body:JSON.stringify(body)});
      var j=await r.json();
      if(!r.ok){ document.getElementById('lab-result').textContent='Error '+r.status+': '+(j.detail||JSON.stringify(j).slice(0,800)); document.getElementById('lab-status').textContent='Error'; }
      else {
        window._lastLabId=j.id;
        var idsEl=document.getElementById('lab-analyze-ids');
        if(idsEl) idsEl.value=(j.event_ids||[]).slice(0,5).join(',');
        var synth = j.is_synthetic ? 'SYNTHETIC' : 'real';
        var det = j.detection_result==='detected'?'DETECTED':j.detection_result==='not_detected'?'NOT DETECTED':j.detection_result;
        document.getElementById('lab-result').textContent = JSON.stringify({id:j.id,test_type:j.test_type,target:j.target_url,synthetic:synth,detection:det,requests:j.request_count,responses:j.response_count,statuses:j.http_statuses,correlation_ids:j.correlation_ids,event_ids:j.event_ids,meta:j.meta},null,2);
        document.getElementById('lab-status').textContent='Done';
        refreshLabRuns();
      }
    }catch(err){ document.getElementById('lab-result').textContent=err.message; document.getElementById('lab-status').textContent='Error'; }
    btn.disabled=false;
  });
  var clearBtn=document.getElementById('lab-clear-btn');
  if(clearBtn) clearBtn.addEventListener('click', function(){ document.getElementById('lab-result').textContent='No test run yet.'; var a=document.getElementById('lab-analyze-result'); if(a) a.textContent='No analysis yet.'; document.getElementById('lab-status').textContent=''; });
})();
