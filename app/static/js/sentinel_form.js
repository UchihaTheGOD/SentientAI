document.getElementById('analyze-form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const btn = document.getElementById('analyze-btn');
  const status = document.getElementById('analyze-status');
  const log_text = document.getElementById('log_text').value;
  const extra_prompt = document.getElementById('extra_prompt').value || null;
  btn.disabled = true; status.textContent = 'Analyzing… (dual-model inference may take ~5-10s)';
  document.getElementById('results').style.display='none';
  try{
    const res = await fetch('/api/sentinel/analyze', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': (document.querySelector('meta[name=csrf-token]')?.content||'')}, body: JSON.stringify({log_text, extra_prompt, max_new_tokens:180})});
    const data = await res.json();
    if(!res.ok){ status.textContent = 'Error: '+(data.detail||JSON.stringify(data)); return; }
    document.getElementById('results').style.display='block';
    document.getElementById('fusion').innerHTML = '<strong>'+(data.verdict||'')+'</strong> (score '+(data.risk_score ?? '')+')';
    document.getElementById('evidence').innerHTML = (data.evidence||[]).map(ev=>'<div>• '+ev+'</div>').join('');
    document.getElementById('disagreement').textContent = 'Agreement: '+(data.agreement===true?'agree':'')+(data.agreement===false?'disagree':data.agreement===null?'n/a':'')+' '+(data.agreement_detail||'')+' — '+((data.fusion&&data.fusion.note)||'');
    document.getElementById('model-a').textContent = (data.model_a && data.model_a.text) || '(no output)';
    document.getElementById('model-a-meta').textContent = (data.model_a && (data.model_a.status+' '+ (data.model_a.latency_ms||'')+'ms '+(data.model_a.error||''))) || '';
    document.getElementById('model-b').textContent = (data.model_b && data.model_b.text) || '(no output)';
    document.getElementById('model-b-meta').textContent = (data.model_b && (data.model_b.status+' '+ (data.model_b.latency_ms||'')+'ms '+(data.model_b.error||''))) || '';
    const inc = data.incident_id ? '<a href="/admin/sentinel/incidents">Incident #'+data.incident_id+' created — review</a>' : 'No incident created';
    document.getElementById('incident-link').innerHTML = inc + ' · latency '+ (data.latency_ms||'')+'ms';
    status.textContent = 'Done';
  }catch(err){ status.textContent = 'Network error: '+err.message; }
  finally{ btn.disabled = false; }
});
