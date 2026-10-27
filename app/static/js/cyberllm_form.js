document.getElementById('analyze-form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const btn = document.getElementById('analyze-btn');
  const status = document.getElementById('analyze-status');
  const log_text = document.getElementById('log_text').value;
  const kind = document.getElementById('kind').value;
  btn.disabled = true; status.textContent = 'Analyzing… (first analysis also loads the model)';
  document.getElementById('results').style.display='none';
  try{
    const res = await fetch('/api/cyberllm/analyze', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': (document.querySelector('meta[name=csrf-token]')?.content||'')}, body: JSON.stringify({log_text, kind})});
    const data = await res.json();
    if(!res.ok){
      const detail = data.detail;
      status.textContent = 'Error ' + res.status + ': ' + (typeof detail === 'string' ? detail : JSON.stringify(detail));
      if (detail && detail.deterministic_findings) {
        document.getElementById('results').style.display='block';
        document.getElementById('verdict').textContent = 'Model unavailable — deterministic findings only';
        document.getElementById('findings').innerHTML = detail.deterministic_findings.map(f=>'<div>• '+f.rule+' ('+f.severity+'): '+f.evidence+'</div>').join('') || '(none)';
      }
      return;
    }
    document.getElementById('results').style.display='block';
    document.getElementById('verdict').textContent = data.classification + ' · confidence ' + data.confidence + ' · via ' + data.decision_source;
    document.getElementById('needs-review').style.display = data.needs_review ? 'block' : 'none';
    document.getElementById('summary').textContent = data.summary || '';
    document.getElementById('meta').textContent = 'parse_ok=' + data.parse_ok + ' · truncated=' + data.truncated + ' · tokens=' + data.output_tokens + ' · latency=' + data.latency_ms + 'ms' + (data.model_classification && data.model_classification !== data.classification ? ' · model said ' + data.model_classification : '') + (data.note ? ' · ' + data.note : '');
    const list = (arr)=> (arr||[]).map(x=>'<div>• '+x+'</div>').join('') || '(none)';
    document.getElementById('indicators').innerHTML = list(data.indicators);
    document.getElementById('reasoning').textContent = data.reasoning || '';
    document.getElementById('limitations').innerHTML = list(data.limitations);
    document.getElementById('actions').innerHTML = list(data.recommended_actions);
    document.getElementById('findings').innerHTML = (data.deterministic_findings||[]).map(f=>'<div>• '+f.rule+' ('+f.severity+'): '+f.evidence+'</div>').join('') || '(none)';
    const raw = document.getElementById('raw');
    if (data.raw_output) { raw.style.display='block'; raw.textContent = data.raw_output; } else { raw.style.display='none'; }
    status.textContent = 'Done';
  }catch(err){ status.textContent = 'Network error: '+err.message; }
  finally{ btn.disabled = false; }
});
