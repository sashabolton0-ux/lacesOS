/* LacesOS optional module entry point.
   Feature logic is being migrated out of system.html in stages.
   This module registers availability with the core without changing identity data. */
(function(){
  const id = "quick-launcher";
  const registry = window.LacesOSModules = window.LacesOSModules || {};
  registry[id] = registry[id] || { id: id, status: "available", initialize: function() { return true; } };
})();
