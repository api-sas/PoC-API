/**
 * Clase Base (Protocolo) para cualquier endpoint de Google API.
 * Identifica dinámicamente las columnas y busca por ID.
 */
class ApiStrategy {
  constructor(name, metricasConfig = []) {
    this.name = name;
    this.metricasConfig = metricasConfig; 
    this.authHeader = null; // NUEVO: Almacenará el token OAuth para llamadas secundarias
  }

  // NUEVO: Método para que el Facade inyecte las credenciales
  setAuthHeader(header) {
    this.authHeader = header;
  }

  getRequestConfig() {
    throw new Error("Método getRequestConfig() debe ser implementado");
  }

  parseResponse(jsonResponse) {
    throw new Error("Método parseResponse() debe ser implementado");
  }

  // NUEVO: Paginador universal. Hace peticiones hasta que no haya nextPageToken.
  fetchPaginated(urlBase, arrayKey) {
    if (!this.authHeader) {
      throw new Error(`[CRÍTICO] No se inyectó authHeader en la estrategia ${this.name}`);
    }

    let resultList = [];
    let nextPageToken = "";

    do {
      let url = urlBase;
      if (nextPageToken) {
        url += (url.includes("?") ? "&" : "?") + "pageToken=" + nextPageToken;
      }

      let options = {
        method: "get",
        headers: this.authHeader,
        muteHttpExceptions: true
      };

      try {
        let response = UrlFetchApp.fetch(url, options);
        let json = JSON.parse(response.getContentText());

        if (json.error) {
          Logger.log(`[ERROR API INTERNO - ${this.name}] ${urlBase}: ${json.error.message}`);
          return null; // Retorna null para que la clase hija maneje el fallo
        }

        let items = json[arrayKey] || [];
        resultList = resultList.concat(items);
        nextPageToken = json.nextPageToken || "";

      } catch (e) {
        Logger.log(`[FALLO DE RED - ${this.name}] Excepción: ${e.message}`);
        return null;
      }
    } while (nextPageToken);

    return resultList;
  }

  writeToSheet(res) {
    // ... [MANTÉN TU CÓDIGO ACTUAL EXACTAMENTE IGUAL AQUÍ] ...
  }

  writeScoreToSheet(spreadsheet, metricaId, scoreValue) {
    // ... [MANTÉN TU CÓDIGO ACTUAL EXACTAMENTE IGUAL AQUÍ] ...
  }
}