document.getElementById("attact-form").addEventListener("submit", async (e)=>{
  e.preventDefault();
  const fd=new FormData(e.target);
  const body={target: fd.get("target")||"http://127.0.0.1:8000", checks: (fd.get("checks")||"").split(",").map(s=>s.trim()).filter(Boolean)};
  document.getElementById("attact-status").textContent="Running";
  const r=await fetch("/api/security/attact/run",{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":document.querySelector("meta[name=csrf-token]")?.content||document.querySelector("[name=csrf_token]")?.value||""},body:JSON.stringify(body)});
  const j=await r.json(); document.getElementById("attact-result").textContent=JSON.stringify(j,null,2).slice(0,7000);
  document.getElementById("attact-status").textContent=r.ok?"Done":"Error";
  if(r.ok) setTimeout(()=>location.reload(),1000);
});
document.querySelectorAll(".demo-btn").forEach(b=>{b.addEventListener("click", async()=>{
  const id=b.dataset.case; const el=document.getElementById("demo-"+id); el.textContent="running"; b.disabled=true;
  try{const r=await fetch("/api/security/demo/run/"+id,{method:"POST",headers:{"X-CSRF-Token":document.querySelector("meta[name=csrf-token]")?.content||""}}); const j=await r.json(); el.textContent=JSON.stringify({gt:j.ground_truth,app:j.app_status,fusion:j.fusion?.fused_verdict},null,1);}catch(e){el.textContent=e.message;} b.disabled=false;
});});
