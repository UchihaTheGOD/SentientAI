/* theme.js — three-way theme (system/light/dark), localStorage + server persistence, no FOUC.
   Inline no-flash snippet in base_public.html sets data-theme before CSS loads;
   this module Hydrates the selector UI, listens for OS changes, and syncs to server.
*/
(function(){
  "use strict";
  var LS_KEY = "sentient_theme";
  var VALID = {system:1, light:1, dark:1};

  function normalize(v){
    v = (v||"").toString().trim().toLowerCase();
    return VALID[v] ? v : "system";
  }
  function applyTheme(choice){
    choice = normalize(choice);
    var el = document.documentElement;
    if(choice === "system"){
      el.removeAttribute("data-theme");
      // let CSS media query decide; also set explicit for JS queries if needed
      el.setAttribute("data-theme", "system");
    } else {
      el.setAttribute("data-theme", choice);
    }
    // also expose resolved for CSS that needs it
    var resolved = resolveEffective(choice);
    el.setAttribute("data-theme-resolved", resolved);
    // keep meta theme-color in sync
    var meta = document.querySelector('meta[name=\"theme-color\"]');
    if(meta) meta.setAttribute("content", resolved === "dark" ? "#0f1115" : "#ffffff");
    return choice;
  }
  function resolveEffective(choice){
    choice = normalize(choice);
    if(choice !== "system") return choice;
    try { return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"; } catch(e){ return "light"; }
  }
  function getStored(){
    try { return normalize(localStorage.getItem(LS_KEY) || "system"); } catch(e){ return "system"; }
  }
  function setStored(v){
    v = normalize(v);
    try { localStorage.setItem(LS_KEY, v); } catch(e){}
    return v;
  }
  function csrfToken(){
    var el = document.querySelector('meta[name=\"csrf-token\"]');
    if(el && el.content) return el.content;
    el = document.querySelector('[name=\"csrf_token\"]');
    if(el && el.value) return el.value;
    return "";
  }
  function syncToServer(choice){
    choice = normalize(choice);
    // fire-and-forget; server stores system as null. Only for authenticated users; anonymous gets 401 ignored.
    try {
      fetch("/api/user/theme", {
        method: "POST",
        headers: {"Content-Type":"application/json","X-CSRF-Token": csrfToken()},
        body: JSON.stringify({theme: choice}),
        credentials: "same-origin"
      }).catch(function(){});
    } catch(e){}
  }
  function reconcileFromServer(){
    // if authenticated, server preference wins over localStorage on first load
    try {
      fetch("/api/user/theme-resolve", {credentials:"same-origin"})
        .then(function(r){ return r.json(); })
        .then(function(j){
          if(j && j.authenticated && VALID[j.theme]){
            var server = normalize(j.theme);
            var local = getStored();
            if(server !== local){
              setStored(server);
              applyTheme(server);
              updateSelector(server);
            }
          }
        }).catch(function(){});
    } catch(e){}
  }

  // OS change listener when in system mode
  var mql = null;
  try { mql = window.matchMedia("(prefers-color-scheme: dark)"); } catch(e){}
  function bindSystemListener(){
    if(!mql) return;
    var handler = function(){
      if(normalize(getStored()) === "system"){
        applyTheme("system");
        updateSelector("system");
      }
    };
    try { mql.addEventListener("change", handler); } catch(e){ try { mql.addListener(handler); } catch(e2){} }
  }

  function updateSelector(choice){
    choice = normalize(choice);
    document.querySelectorAll("[data-theme-selector]").forEach(function(root){
      root.querySelectorAll("[data-theme-value]").forEach(function(btn){
        var isActive = btn.getAttribute("data-theme-value") === choice;
        btn.setAttribute("aria-pressed", isActive ? "true" : "false");
        btn.classList.toggle("theme-opt--active", isActive);
      });
      var label = root.querySelector("[data-theme-current]");
      if(label){
        label.textContent = choice.charAt(0).toUpperCase()+choice.slice(1);
      }
      // for <select> variant
      var sel = root.querySelector("select");
      if(sel) sel.value = choice;
    });
  }

  function initSelectors(){
    document.querySelectorAll("[data-theme-selector]").forEach(function(root){
      // button group
      root.querySelectorAll("[data-theme-value]").forEach(function(btn){
        btn.addEventListener("click", function(){
          var v = normalize(btn.getAttribute("data-theme-value"));
          setStored(v);
          applyTheme(v);
          updateSelector(v);
          syncToServer(v);
        });
      });
      // select dropdown variant (if present)
      var sel = root.querySelector("select");
      if(sel){
        sel.addEventListener("change", function(){
          var v = normalize(sel.value);
          setStored(v);
          applyTheme(v);
          updateSelector(v);
          syncToServer(v);
        });
      }
    });
  }

  // Early apply from localStorage (inline script already did, but re-apply for modules that load late)
  var initial = getStored();
  applyTheme(initial);

  if(document.readyState === "loading"){
    document.addEventListener("DOMContentLoaded", function(){
      updateSelector(getStored());
      initSelectors();
      bindSystemListener();
      reconcileFromServer();
    });
  } else {
    updateSelector(getStored());
    initSelectors();
    bindSystemListener();
    reconcileFromServer();
  }

  // expose for tests / console
  window.SentientTheme = {
    get: function(){ return normalize(getStored()); },
    set: function(v){ v=normalize(v); setStored(v); applyTheme(v); updateSelector(v); syncToServer(v); return v; },
    resolved: function(){ return resolveEffective(getStored()); },
    apply: applyTheme
  };
})();
