function labCsrf(){return document.querySelector('meta[name=csrf-token]')?.content||'';}
async function refreshLabRuns(){
  try{
    const r=await fetch('/api/security/lab/runs?limit=10',{headers:{'X-CSRF-Token': labCsrf()}});
    const j=await r.json();
    const el=document.getElementById('lab-runs-list');
    if(!j.items||!j.items.length){el.textContent='No runs yet.';return;}
    el.innerHTML=j.items.map(function(x){
      var b=x.is_synthetic?'badge-yellow':'badge-gray';
      var d=x.detection_result=='detected'?'badge-green':(x.detection_result=='synthetic'?'badge-yellow':'badge-gray');
      var h='<div style="border:1px solid #e5e7eb;border-radius:6px;padding:6px;margin-bottom:6px">';
      h+='<span class="mono">#'+x.id+' '+x.test_type+'</span> ';
      h+='<span class="badge '+b+'">'+(x.is_synthetic?'synthetic':'real')+'</span> ';
      h+='<span class="badge '+d+'">'+x.detection_result+'</span> ';
      h+='<span class="text-xs">req '+x.request_count+' resp '+x.response_count+' sts '+JSON.stringify(x.http_statuses)+'</span> ';
      h+='<span class="text-xs">'+(x.created_at||'')+'</span>';
      h+='<div class="text-xs mono">target '+x.target_url+' events '+JSON.stringify(x.event_ids).slice(0,120)+'</div>';
      if(x.error) h+='<div class="text-xs" style="color:#dc2626">'+x.error.slice(0,300)+'</div>';
      h+='</div>'; return h;
    }).join('');
  }catch(e){var el=document.getElementById('lab-runs-list');if(el)el.textContent=e.message;}
}
