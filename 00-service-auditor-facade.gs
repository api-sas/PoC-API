class SecurityAuditorFacade {
  constructor(authService) {
    this.auth = authService;
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
      const config = s.getRequestConfig();
      
      // SOLUCIÓN DE CACHÉ: Fusionamos el Token OAuth con directivas estrictas anti-caché.
      // Esto obliga a UrlFetchApp y a los servidores de Google a traer el último cambio de la consola.
      config.headers = {
        ...(config.headers || {}),
        ...authHeader,
        "Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
        "Pragma": "no-cache"
      };
      
      // Inyectamos todas las cabeceras a la estrategia para sus llamadas secundarias paginadas
      if (typeof s.setAuthHeader === 'function') {
        s.setAuthHeader(config.headers);
      }

      try {
        const response = UrlFetchApp.fetch(config.url, config);
        const json = JSON.parse(response.getContentText());
        const parsedRes = s.parseResponse(json);        
        
        resultados.push(parsedRes);
        s.writeToSheet(parsedRes);        
      } catch (e) {
        Logger.log(`Error de red en ${s.name}: ${e.message}`);
        const errorRes = s.parseResponse({ error: { message: e.message } });        
        resultados.push(errorRes);
        s.writeToSheet(errorRes);
      }      
      
      if (i < this.strategies.length - 1) {
        Utilities.sleep(1000); 
      }
    }
    return resultados;
  }
}