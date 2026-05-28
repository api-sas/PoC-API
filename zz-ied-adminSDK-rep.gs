/**
 * Auditoría Avanzada de Seguridad en Google Workspace (Índice de Exposición de Datos - IED)
 * VERSIÓN ADMIN SDK REPORTS API (Últimos 180 días) 
 * ARQUITECTURA: Esquema Plano (10 Cols) + Deduplicación de Doble Capa + Tabla IED
 */

const auth = new AuthService();
const CORPORATE_DOMAIN = auth.getDomain();
const SHEET_NAME = "Auditoria IED global";
const MAX_EXEC_TIME_MS = 4.0 * 60 * 1000; // 4 minutos exactos para garantizar margen de cierre
const DAYS_TO_RETRIEVE = 180; // Rango histórico de 6 meses

function AuditoriaIEDGlobal() {
  Logger.log("=== INICIANDO AUDITORÍA IED (ADMIN SDK REPORTS API) ===");
  let ui = null;
  
  try {
    ui = SpreadsheetApp.getUi();
  } catch (e) {
    // Se ejecuta en segundo plano
  }

  const scriptProperties = PropertiesService.getScriptProperties();
  let isFinished = scriptProperties.getProperty('isFinished');
  let pageToken = scriptProperties.getProperty('pageToken') || null;

  if (isFinished === 'true') {
    if (ui) ui.alert("✅ El Índice de Exposición de Datos histórico ya está completo y actualizado.");
    scriptProperties.deleteAllProperties();
    return;
  }

  // Ejecución Inicial: Limpiamos la hoja y fijamos la ventana de 180 días en memoria
  if (!pageToken && !scriptProperties.getProperty('startTimeIso')) {
    inicializarHojaIED();
    
    let endDate = new Date();
    let startDate = new Date();
    startDate.setDate(endDate.getDate() - DAYS_TO_RETRIEVE);
    
    scriptProperties.setProperty('startTimeIso', startDate.toISOString());
    scriptProperties.setProperty('endTimeIso', endDate.toISOString());
  }

  const startTime = Date.now(); 
  const startTimeIso = scriptProperties.getProperty('startTimeIso');
  const endTimeIso = scriptProperties.getProperty('endTimeIso');
  
  while (Date.now() - startTime < MAX_EXEC_TIME_MS) { 
    let optionalArgs = {
      userKey: 'all',
      startTime: startTimeIso,
      endTime: endTimeIso,
      maxResults: 1000
    };
    
    if (pageToken) optionalArgs.pageToken = pageToken;

    let response = ejecutarReportsAPIConBackoff('drive', optionalArgs);
    
    if (!response) {
      Logger.log("[ERROR CRÍTICO] La red rechazó múltiples reintentos. Deteniendo ejecución."); 
      isFinished = 'error';
      break;
    }

    let activities = response.items || [];
    if (activities.length > 0) {
      Logger.log(`[PROCESANDO] ${activities.length} eventos obtenidos en la API...`);
      // CAPA 1: Deduplicación en Memoria (Evita saturar la hoja de Google Sheets)
      let procesados = procesarActividadesReports(activities);
      
      if (procesados.length > 0) {
        escribirEnHojaActiva(procesados);
        SpreadsheetApp.flush(); 
      }
    }

    pageToken = response.nextPageToken; 
    if (!pageToken) {
      Logger.log(`[INFO] Se ha extraído la totalidad del historial disponible de 180 días.`);
      isFinished = 'true';
      break;
    }
  }

  // ===============================================
  // LÓGICA DE FINALIZACIÓN Y DEDUPLICACIÓN GLOBAL
  // ===============================================
  if (isFinished === 'true') {
    Logger.log("=== INICIANDO FASE DE CONSOLIDACIÓN GLOBAL ===");
    
    // CAPA 2: Unifica cualquier remanente histórico (Garantiza 1 solo ID por fila)
    consolidarDatosUnicos();
    
    // Inyecta la tabla resumen con porcentajes e IED
    crearTablaResumenM();
    
    scriptProperties.deleteAllProperties();
    Logger.log("=== AUDITORÍA IED COMPLETADA CON ÉXITO ===");
    if (ui) ui.alert("✅ Índice de Exposición de Datos completado. Archivos unificados exitosamente.");
    
  } else if (isFinished === 'error') {
    scriptProperties.deleteAllProperties();
  } else {
    // Si el tiempo se agota, guardamos el token y programamos la continuación
    if (pageToken) scriptProperties.setProperty('pageToken', pageToken);
    
    let triggers = ScriptApp.getProjectTriggers();
    triggers.forEach(trigger => {
      if(trigger.getHandlerFunction() === 'AuditoriaIEDGlobal') ScriptApp.deleteTrigger(trigger);
    });

    ScriptApp.newTrigger('AuditoriaIEDGlobal') 
             .timeBased()
             .after(1 * 60 * 1000) 
             .create();
  }
}

// ==========================================
// UTILIDAD: JERARQUÍA DE RIESGO
// ==========================================
function getHighestVisibility(v1, v2) {
  const levels = {
    'Private': 1,
    'shared_internally': 2,
    'people_within_domain_with_link': 3,
    'externally': 4,
    'people_with_link': 5,
    'public_on_the_web': 6
  };
  let val1 = levels[v1] || 0;
  let val2 = levels[v2] || 0;
  return val1 > val2 ? v1 : v2;
}

// ==========================================
// CAPA 1: EXTRACCIÓN Y DEDUPLICACIÓN EN MEMORIA
// ==========================================
function procesarActividadesReports(activities) {
  let mapChunk = new Map();

  activities.forEach(activity => {
    try {
      let date = activity.id.time;
      let actorEmail = activity.actor ? activity.actor.email : 'Desconocido';
      let events = activity.events || [];

      events.forEach(event => {
        let eventName = event.name;
        
        let isPrimary = getParamValue(event.parameters, 'primary_event');
        if (!isPrimary || (eventName !== 'change_user_access' && eventName !== 'change_document_visibility')) {
          return; 
        }

        let docTitle = getParamValue(event.parameters, 'doc_title') || getParamValue(event.parameters, 'resource_title') || 'N/A';
        let docId = getParamValue(event.parameters, 'doc_id') || getParamValue(event.parameters, 'resource_id') || 'N/A';
        
        if (docId === 'N/A') return;

        let visibility = getParamValue(event.parameters, 'visibility') || 'Private';
        let recipientRaw = "";

        if (visibility === 'people_with_link' || visibility === 'public_on_the_web') {
          recipientRaw = "anyone";
        } else {
          recipientRaw = getParamValue(event.parameters, 'target_user') || 'N/A';
        }

        let destinatarios = [];
        if (typeof recipientRaw === 'string') {
          destinatarios = recipientRaw.split(',').map(r => r.trim()).filter(r => r !== '' && r !== 'N/A');
        } else if (recipientRaw) {
          destinatarios = [String(recipientRaw)];
        }

        let compartidoExternoFlag = evaluarExposicionExterna(destinatarios);
        let anyoneFlag = (destinatarios.includes("anyone") || visibility === 'people_with_link' || visibility === 'public_on_the_web');

        // AGRUPACIÓN EN MEMORIA (Evita generar filas duplicadas inmediatas)
        if (!mapChunk.has(docId)) {
           mapChunk.set(docId, {
              date: date,
              actor: actorEmail,
              docTitle: docTitle,
              visibility: visibility,
              destinatarios: new Set(destinatarios),
              externo: compartidoExternoFlag,
              cualquiera: anyoneFlag
           });
        } else {
           let existing = mapChunk.get(docId);
           // Actualizar fecha si es más reciente
           if (new Date(date) > new Date(existing.date)) {
               existing.date = date;
               existing.actor = actorEmail;
           }
           // Unir destinatarios
           destinatarios.forEach(d => existing.destinatarios.add(d));
           // Conservar banderas de riesgo
           if (compartidoExternoFlag) existing.externo = true;
           if (anyoneFlag) existing.cualquiera = true;
           // Elevar visibilidad
           existing.visibility = getHighestVisibility(existing.visibility, visibility);
        }
      });
    } catch (e) {
      Logger.log(`[ERROR EN EVENTO] ${e.message}`);
    }
  });

  // Convertir el Mapa limpio en matriz para Sheets
  let filas = [];
  mapChunk.forEach((val, docId) => {
      let strCualquiera = val.cualquiera ? "Sí" : "No";
      let strExterno = val.externo ? "Sí" : "No";

      let riesgo = "Bajo";
      if (val.cualquiera) {
        riesgo = "Alto"; 
      } else if (val.externo) {
        riesgo = "Medio"; 
      }
      
      let destArray = Array.from(val.destinatarios).filter(r => r !== '');
      let destFinal = destArray.length > 0 ? destArray.join(', ') : "Ninguno";

      filas.push([
        val.date,                  
        val.actor,            
        "Google Drive",        
        docId,                 
        val.docTitle,              
        val.visibility,            
        destFinal, 
        strExterno,            
        strCualquiera,         
        riesgo                 
      ]);
  });

  return filas;
}

// ==========================================
// CAPA 2: DEDUPLICACIÓN GLOBAL FINAL
// ==========================================
function consolidarDatosUnicos() {
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return;

  let data = sheet.getDataRange().getValues();
  if (data.length <= 1) return; // Solo hay cabeceras

  let headers = data.shift(); 
  let mapGlobal = new Map();

  // Agrupamos absolutamente todas las filas escritas históricamente
  data.forEach(row => {
    let docId = String(row[3]).trim();
    if (!docId || docId === 'N/A') return;

    let fecha = row[0];
    let actor = row[1];
    let titulo = row[4];
    let visibilidad = row[5];
    let destinatariosStr = String(row[6]);
    let esExterno = row[7] === 'Sí';
    let esPublico = row[8] === 'Sí';

    if (!mapGlobal.has(docId)) {
      let destSet = new Set();
      if (destinatariosStr && destinatariosStr !== 'Ninguno' && destinatariosStr !== 'N/A') {
        destinatariosStr.split(',').forEach(d => destSet.add(d.trim()));
      }

      mapGlobal.set(docId, {
        fecha: fecha,
        actor: actor,
        titulo: titulo,
        visibilidad: visibilidad,
        destinatarios: destSet,
        externo: esExterno,
        publico: esPublico
      });
    } else {
      let docObj = mapGlobal.get(docId);
      
      let dateExisting = new Date(docObj.fecha);
      let dateNew = new Date(fecha);
      if (dateNew > dateExisting) {
        docObj.fecha = fecha;
        docObj.actor = actor;
      }
      
      if (destinatariosStr && destinatariosStr !== 'Ninguno' && destinatariosStr !== 'N/A') {
        destinatariosStr.split(',').forEach(d => {
            if(d.trim() !== "") docObj.destinatarios.add(d.trim());
        });
      }
      
      if (esExterno) docObj.externo = true;
      if (esPublico) docObj.publico = true;
      docObj.visibilidad = getHighestVisibility(docObj.visibilidad, visibilidad);
    }
  });

  let matrizConsolidada = [];
  mapGlobal.forEach((obj, docId) => {
    let strCualquiera = obj.publico ? "Sí" : "No";
    let strExterno = obj.externo ? "Sí" : "No";
    
    let riesgo = "Bajo";
    if (obj.publico) {
      riesgo = "Alto";
    } else if (obj.externo) {
      riesgo = "Medio";
    }

    let destArray = Array.from(obj.destinatarios).filter(r => r !== '');
    let destFinal = destArray.length > 0 ? destArray.join(', ') : "Ninguno";

    matrizConsolidada.push([
      obj.fecha, obj.actor, "Google Drive", docId, obj.titulo, 
      obj.visibilidad, destFinal, strExterno, strCualquiera, riesgo
    ]);
  });

  // Limpiamos la hoja sucia y reescribimos solo los IDs únicos
  sheet.clearContents();
  sheet.appendRow(headers);
  if (matrizConsolidada.length > 0) {
    sheet.getRange(2, 1, matrizConsolidada.length, 10).setValues(matrizConsolidada);
  }
  SpreadsheetApp.flush();
  Logger.log(`[DEDUPLICACIÓN FINAL] Hoja unificada a ${matrizConsolidada.length} archivos únicos.`);
}

// ==========================================
// FUNCIÓN DE PREPARACIÓN DE PESTAÑA
// ==========================================
function inicializarHojaIED() {
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  
  if (sheet) {
    sheet.clear(); 
  } else {
    sheet = ss.insertSheet(SHEET_NAME);
  }
  
  sheet.appendRow([
    "Fecha Último Evento", "Actor", "Aplicación", "ID Documento", 
    "Titulo del recurso", "Visibilidad/Severidad", "Destinatario(s)", 
    "Compartido con Externo", "Cualquiera con el Enlace", "Criterio de Riesgo"
  ]);
  sheet.getRange(1, 1, 1, 10).setFontWeight("bold").setBackground("#edf2f7");
}

// ==========================================
// CONSTRUCCIÓN DE TABLA RESUMEN IED (COLUMNA M)
// ==========================================
function crearTablaResumenM() {
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return;

  let resumenMatriz = [
    ["Resumen de Reglas e Índice de Exposición", "", ""],
    ["Criterio de Riesgo", "Cantidad de Archivos", "Porcentaje (%)"],
    ["🔴 Alto", '=COUNTIF(J2:J, "Alto")', '=IF(N$7>0, N4/N$7, 0)'],
    ["🟡 Medio", '=COUNTIF(J2:J, "Medio")', '=IF(N$7>0, N5/N$7, 0)'],
    ["🟢 Bajo", '=COUNTIF(J2:J, "Bajo")', '=IF(N$7>0, N6/N$7, 0)'],
    ["Total General", '=SUM(N4:N6)', '="IED: " & TEXT(IF(N7>0, (N4+N5)/N7, 0), "0.00%")']
  ];

  let filaInicio = 2;
  let colInicio = 13; // Columna M
  
  let rangoTabla = sheet.getRange(filaInicio, colInicio, resumenMatriz.length, 3);
  rangoTabla.setValues(resumenMatriz);

  let rangoTitulo = sheet.getRange(filaInicio, colInicio, 1, 3);
  rangoTitulo.merge();
  rangoTitulo.setBackground("#1a365d").setFontColor("#ffffff").setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio, 30);

  let rangoHeaders = sheet.getRange(filaInicio + 1, colInicio, 1, 3);
  rangoHeaders.setBackground("#2b6cb0").setFontColor("#ffffff").setFontWeight("bold").setHorizontalAlignment("center").setVerticalAlignment("middle");
  sheet.setRowHeight(filaInicio + 1, 24);

  sheet.getRange(filaInicio + 2, colInicio, 3, 1).setFontWeight("bold").setHorizontalAlignment("left"); 
  sheet.getRange(filaInicio + 2, colInicio + 1, 4, 1).setHorizontalAlignment("center").setFontWeight("bold"); 
  sheet.getRange(filaInicio + 2, colInicio + 2, 3, 1).setHorizontalAlignment("center").setNumberFormat("0.00%");

  let filaTotalNum = filaInicio + resumenMatriz.length - 1;
  sheet.getRange(filaTotalNum, colInicio, 1, 3).setBackground("#edf2f7").setFontWeight("bold");
  sheet.getRange(filaTotalNum, colInicio + 1).setFontColor("#2b6cb0"); 
  sheet.getRange(filaTotalNum, colInicio + 2).setFontColor("#e53e3e").setHorizontalAlignment("center"); 
  sheet.setRowHeight(filaTotalNum, 26);

  rangoTabla.setBorder(true, true, true, true, true, true, "#cbd5e0", SpreadsheetApp.BorderStyle.SOLID);
  sheet.setColumnWidth(13, 140); 
  sheet.setColumnWidth(14, 160); 
  sheet.setColumnWidth(15, 160); 
}

// ==========================================
// RETROCESO EXPONENCIAL TRUNCADO
// ==========================================
function ejecutarReportsAPIConBackoff(applicationName, optionalArgs) {
  let intentos = 0;
  let maxIntentos = 6; 
  while (intentos < maxIntentos) {
    try {
      return AdminReports.Activities.list('all', applicationName, optionalArgs); 
    } catch (e) {
      let errorMsg = e.message.toLowerCase();
      if (errorMsg.includes('403') || errorMsg.includes('429') || errorMsg.includes('rate limit') || errorMsg.includes('too many') || errorMsg.includes('backend error')) {
        let pausa = Math.pow(2, intentos) * 1000 + (Math.random() * 1000); 
        Utilities.sleep(pausa); 
        intentos++;
      } else {
        return null;
      }
    }
  }
  return null; 
}

// ==========================================
// MÉTODOS AUXILIARES
// ==========================================
function getParamValue(parameters, paramName) {
  if (!parameters) return null;
  let param = parameters.find(p => p.name === paramName);
  if (!param) return null;
  return param.value || param.multiValue || param.boolValue || param.intValue;
}

function evaluarExposicionExterna(recipientsArray) {
  for (let i = 0; i < recipientsArray.length; i++) {
    let email = recipientsArray[i].toLowerCase();
    if (email === "anyone" || email === "ninguno") continue;
    
    let partes = email.split('@');
    if (partes.length === 2) {
      let dominio = partes[1];
      if (dominio !== CORPORATE_DOMAIN.toLowerCase()) return true;
    } else {
       return true; 
    }
  }
  return false;
}

function escribirEnHojaActiva(matrizDatos) {
  let ss = SpreadsheetApp.getActiveSpreadsheet();
  if (!ss) return;
  let sheet = ss.getSheetByName(SHEET_NAME);
  if (!sheet) return; 
  
  let ultimaFila = Math.max(sheet.getLastRow(), 1); 
  try {
    sheet.getRange(ultimaFila + 1, 1, matrizDatos.length, matrizDatos[0].length).setValues(matrizDatos);
  } catch (e) {
    Logger.log(`[ERROR]: ${e.message}`);
  }
}