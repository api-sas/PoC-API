class SecurityAuditorFacade {
  constructor(authService, globalContext = null) {
    this.auth = authService;
    this.globalContext = globalContext; // Almacenamos el contexto
    this.strategies = [];
  }

  addStrategy(strategy) {
    this.strategies.push(strategy);
  }

  ejecutarTodo() {
    const resultados = [];
    const authHeader = this.auth.getAuthHeader();

    for (let i = 0; i < this.strategies.length; i++) {
      const s = this.strategies[i];

      try {
        let parsedRes;

        // === BIFURCACIÓN DE PARADIGMAS ===
        // Si la estrategia declara ser de tipo "In-Memory", usamos el motor local
        if (typeof s.evaluateInMemory === 'function') {
          Logger.log(`[FACADE] Ejecutando estrategia en memoria: ${s.name}`);
          parsedRes = s.evaluateInMemory(this.globalContext);
        } 
        // Si es tradicional, usamos la red (UrlFetchApp)
        else {
          Logger.log(`[FACADE] Ejecutando estrategia por red: ${s.name}`);
          const config = s.getRequestConfig();
          config.headers = {
            ...(config.headers || {}),
            ...authHeader,
            "Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
            "Pragma": "no-cache"
          };

          if (typeof s.setAuthHeader === 'function') {
            s.setAuthHeader(config.headers);
          }

          const response = UrlFetchApp.fetch(config.url, config);
          const json = JSON.parse(response.getContentText());
          parsedRes = s.parseResponse(json);
          
          // Pausamos la red solo para estrategias tradicionales
          if (i < this.strategies.length - 1) {
            Utilities.sleep(1000); 
          }
        }

        resultados.push(parsedRes);
        s.writeToSheet(parsedRes);        

      } catch (e) {
        Logger.log(`Error en ${s.name}: ${e.message}`);
        // ... manejo de error (igual al tuyo) ...
      }      
    }
    return resultados;
  }
}