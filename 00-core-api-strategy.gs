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
    if (!this.metricasConfig || !Array.isArray(this.metricasConfig) || this.metricasConfig.length === 0) {
      Logger.log(`[OMITIDO] ${this.name}: No tiene matriz de configuración de IDs válida.`);
      return;
    }

    const sheetName = "Google Workspace Configuraciones de Seguridad";
    const spreadsheet = SpreadsheetApp.getActiveSpreadsheet();
    const sheet = spreadsheet.getSheetByName(sheetName);

    if (!sheet) {
      Logger.log(`[ERROR] No se encontró la pestaña '${sheetName}'.`);
      return;
    }

    // CORRECCIÓN: Se agrega [0] para extraer la fila plana
    const headers = sheet.getRange(2, 1, 1, sheet.getLastColumn()).getValues()[0];
    let colId = -1, colSetting = -1, colNotes = -1, colRisk = -1;

    headers.forEach((header, index) => {
      const h = header.toString().toLowerCase().trim();
      if (h === 'id' || h === 'd') {
        colId = index + 1;
      } else if (h.includes('customer setting') || h.includes('configuración') || h.includes('configuracion') || h.includes('setting')) {
        colSetting = index + 1;
      } else if (h.includes('note') || h.includes('nota') || h.includes('comment')) {
        colNotes = index + 1;
      } else if (h.includes('level of risk') || h.includes('nivel de riesgo')) {
        colRisk = index + 1;
      }
    });

    if (colId === -1 || colSetting === -1) {
      Logger.log(`[ERROR] ${this.name}: No se encontró la columna 'ID' o 'Customer Setting' en la cabecera.`);
      return;
    }

    const idValues = sheet.getRange(1, colId, sheet.getLastRow(), 1).getValues();

    this.metricasConfig.forEach(metrica => {
      let filaDestino = -1;
      for (let i = 0; i < idValues.length; i++) {
        // CORRECCIÓN: Se agrega [0] para acceder al valor de la celda en la columna
        if (idValues[i][0] && idValues[i][0].toString().trim() === metrica.id) {
          filaDestino = i + 1;
          break;
        }
      }

      if (filaDestino !== -1) {
        // Escribir Estado
        if (metrica.valueKey && res[metrica.valueKey] !== undefined) {
          sheet.getRange(filaDestino, colSetting).setValue(res[metrica.valueKey]);
        }
        // Escribir Nota
        if (colNotes !== -1 && metrica.noteKey && res[metrica.noteKey] !== undefined) {
          sheet.getRange(filaDestino, colNotes).setValue(res[metrica.noteKey]);
        }
        // NUEVO: Escribir Nivel de Riesgo
        if (colRisk !== -1 && metrica.riskKey && res[metrica.riskKey] !== undefined) {
          sheet.getRange(filaDestino, colRisk).setValue(res[metrica.riskKey]);
        }
        
        Logger.log(`[ÉXITO] ${this.name}: ID '${metrica.id}' actualizado en la fila ${filaDestino}.`);

        // NUEVO: Escribir en la hoja de Scores
        if (metrica.scoreKey && res[metrica.scoreKey] !== undefined) {
          this.writeScoreToSheet(spreadsheet, metrica.id, res[metrica.scoreKey]);
        }
      } else {
        Logger.log(`[OMITIDO] ${this.name}: ID '${metrica.id}' no se encontró en la hoja principal.`);
      }
    });
  }

  // MÉTODO PARA ESCRIBIR EN LA PESTAÑA SCORES
  writeScoreToSheet(spreadsheet, metricaId, scoreValue) {
    const scoreSheet = spreadsheet.getSheetByName("Scores");
    if (!scoreSheet) {
      Logger.log(`[ERROR] ${this.name}: No se encontró la pestaña 'Scores'.`);
      return;
    }

    // CORRECCIÓN: Faltaba el [0] para leer la fila de cabeceras correctamente
    const scoreHeaders = scoreSheet.getRange(1, 1, 1, scoreSheet.getLastColumn()).getValues()[0];
    let colIdentity = -1;

    scoreHeaders.forEach((header, index) => {
      const h = header.toString().toLowerCase().trim();
      if (h.includes('level of risks identity')) {
        colIdentity = index + 1;
      }
    });

    if (colIdentity !== -1) {
      const idScoresValues = scoreSheet.getRange(1, colIdentity, Math.max(scoreSheet.getLastRow(), 1), 1).getValues();
      let filaScoreDestino = -1;

      for (let i = 0; i < idScoresValues.length; i++) {
        // CORRECCIÓN: Faltaba el [0]
        if (idScoresValues[i][0] && idScoresValues[i][0].toString().trim() === metricaId) {
          filaScoreDestino = i + 1;
          break;
        }
      }

      if (filaScoreDestino === -1) {
        filaScoreDestino = scoreSheet.getLastRow() + 1;
        scoreSheet.getRange(filaScoreDestino, colIdentity).setValue(metricaId);
      }

      scoreSheet.getRange(filaScoreDestino, colIdentity + 1).setValue(scoreValue);
      Logger.log(`[ÉXITO] Score de ${scoreValue} guardado para el ID '${metricaId}'.`);
    } else {
      Logger.log(`[ERROR] No se encontró la cabecera 'level of risks identity' en la pestaña Scores.`);
    }
  }
}