/* log analyzer + lab analyze */
(function(){
  var analyzeBtn=document.getElementById('lab-analyze-btn');
  if(analyzeBtn) analyzeBtn.addEventListener('click', async function(){
    var idsRaw=(document.getElementById('lab-analyze-ids').value||'').trim();
    var el=document.getElementById('lab-analyze-result'); el.textContent='Analyzing with Sentinel...';
    var body={};
    if(idsRaw){ var ids=idsRaw.split(',').map(function(s){return parseInt(s.trim(),10);}).filter(function(n){return !isNaN(n);}); body={event_ids:ids}; }
    else if(window._lastLabId){ body={lab_run_id:window._lastLabId}; }
    else { el.textContent='No run or event IDs selected.'; return; }
    try{
      var r=await fetch('/api/security/lab/analyze',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token': labCsrf()},body:JSON.stringify(body)});
      var j=await r.json();
      if(!r.ok){ el.textContent='Error '+r.status+': '+(j.detail||JSON.stringify(j).slice(0,1200)); return; }
      var ma=j.model_a||{}; var mb=j.model_b||{};
      el.textContent = JSON.stringify({incident_id:j.incident_id,training_candidate_id:j.training_candidate_id,prompt_path:j.prompt_path,prompt_chars:j.prompt_chars,prompt_truncated:j.prompt_truncated,ready:j.ready,latency_ms:j.latency_ms,model_a:{status:ma.status,text:(ma.text||'').slice(0,700),latency_ms:ma.latency_ms,error:ma.error},model_b:{status:mb.status,text:(mb.text||'').slice(0,700),latency_ms:mb.latency_ms,error:mb.error},fusion:j.fusion},null,2);
    }catch(err){ el.textContent=err.message; }
  });
  refreshLabRuns();
  var sampBtn=document.getElementById('log-sample-btn');
  if(sampBtn) sampBtn.addEventListener('click', function(){ document.getElementById('log-input').value='2024-01-01 12:00:00 WARN 203.0.113.7 Failed login for alice 401\n2024-01-01 12:01:00 WARN 203.0.113.7 Failed login for alice 401\n2024-01-01 12:04:00 INFO 203.0.113.7 Login success for alice 200'; });
  var clrLog=document.getElementById('log-clear-btn');
  if(clrLog) clrLog.addEventListener('click', function(){ document.getElementById('log-input').value=''; document.getElementById('log-result').textContent='No analysis yet.'; document.getElementById('log-status').textContent=''; });
  var fileEl=document.getElementById('log-file');
  if(fileEl) fileEl.addEventListener('change', async function(e){
    var f=e.target.files[0]; if(!f) return;
    if(f.size>64*1024){ document.getElementById('log-status').textContent='File too large (>64KB)'; return; }
    var t=await f.text(); document.getElementById('log-input').value=t.slice(0,8000);
  });
  var logBtn=document.getElementById('log-analyze-btn');
  if(logBtn) logBtn.addEventListener('click', async function(){
    var txt=(document.getElementById('log-input').value||'').trim();
    var el=document.getElementById('log-result'); var st=document.getElementById('log-status');
    if(!txt){ el.textContent='Enter log text.'; return; }
    if(txt.length>8000){ el.textContent='Log too long (>8000)'; return; }
    el.textContent='Analyzing...'; st.textContent='Running models...';
    var btn=document.getElementById('log-analyze-btn'); btn.disabled=true;
    try{
      var r=await fetch('/api/security/lab/log-analyze',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token': labCsrf()},body:JSON.stringify({log_text:txt})});
      var j=await r.json();
      if(!r.ok){ el.textContent='Error '+r.status+': '+(j.detail||JSON.stringify(j).slice(0,1200)); st.textContent='Error'; }
      else {
        var ma=j.model_a||{}; var mb=j.model_b||{};
        el.textContent = JSON.stringify({incident_id:j.incident_id,training_candidate_id:j.training_candidate_id,prompt_path:j.prompt_path,prompt_chars:j.prompt_chars,prompt_truncated:j.prompt_truncated,model_a:{status:ma.status,text:(ma.text||'').slice(0,900),latency_ms:ma.latency_ms},model_b:{status:mb.status,text:(mb.text||'').slice(0,900),latency_ms:mb.latency_ms},fusion:j.fusion,latency_ms:j.latency_ms},null,2);
        st.textContent='Done';
      }
    }catch(err){ el.textContent=err.message; st.textContent='Error'; }
    btn.disabled=false;
  });
})();
