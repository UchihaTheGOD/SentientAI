document.getElementById('analyze-form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const btn = document.getElementById('analyze-btn');
  const status = document.getElementById('analyze-status');
  const log_text = document.getElementById('log_text').value;
  btn.disabled = true; status.textContent = 'Analyzing… (CyberLLMv1 inference may take a while on first load)';
  document.getElementById('results').style.display='none';
  try{
    const res = await fetch('/api/sentinel/analyze', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': (document.querySelector('meta[name=csrf-token]')?.content||'')}, body: JSON.stringify({log_text, max_new_tokens:256})});
    const data = await res.json();
    if(!res.ok){ status.textContent = 'Error: '+(data.detail||JSON.stringify(data)); return; }
    document.getElementById('results').style.display='block';
    document.getElementById('fusion').innerHTML = '<strong>'+(data.verdict||'')+'</strong> (score '+(data.risk_score ?? '')+')';
    document.getElementById('evidence').innerHTML = (data.evidence||[]).map(ev=>'<div>• '+ev+'</div>').join('');
    document.getElementById('classification-line').textContent = ((data.classification&&data.classification.source)||'')+' status: '+((data.classification&&data.classification.status)||'')+' — '+((data.fusion&&data.fusion.note)||'');
    document.getElementById('classification').textContent = (data.classification && (data.classification.classification+' ('+data.classification.confidence+') — '+data.classification.summary)) || '(no output)';
    document.getElementById('classification-meta').textContent = (data.classification && (data.classification.status+' '+ (data.classification.latency_ms||'')+'ms')) || '';
    const inc = data.incident_id ? '<a href="/admin/sentinel/incidents">Incident #'+data.incident_id+' created — review</a>' : 'No incident created';
    document.getElementById('incident-link').innerHTML = inc + ' · latency '+ (data.latency_ms||'')+'ms';
    status.textContent = 'Done';
  }catch(err){ status.textContent = 'Network error: '+err.message; }
  finally{ btn.disabled = false; }
});
