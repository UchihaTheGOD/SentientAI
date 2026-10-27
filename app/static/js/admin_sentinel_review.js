document.querySelectorAll('form[data-review]').forEach(f=>{
  f.addEventListener('submit', async (e)=>{
    e.preventDefault();
    const fd = new FormData(f);
    const status = fd.get('status'); const note = fd.get('note');
    const url = f.getAttribute('action');
    const res = await fetch(url, {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': document.querySelector('[name=csrf_token]')?.value || ''}, body: JSON.stringify({status, note})});
    const data = await res.json();
    if(res.ok){ location.reload(); } else { alert(data.detail||JSON.stringify(data)); }
  });
});
document.getElementById('block-form').addEventListener('submit', async (e)=>{
  e.preventDefault();
  const fd = new FormData(e.target);
  const body = {kind: fd.get('kind'), value: fd.get('value'), ttl_minutes: parseInt(fd.get('ttl_minutes')||'30',10), reason: fd.get('reason')||null};
  const res = await fetch('/api/sentinel/blocks', {method:'POST', headers:{'Content-Type':'application/json', 'X-CSRF-Token': document.querySelector('[name=csrf_token]')?.value || ''}, body: JSON.stringify(body)});
  const data = await res.json();
  if(res.ok) location.reload(); else alert(data.detail||JSON.stringify(data));
});
