/**
 * Estrategia para auditar la exposición de Grupos Empresariales.
 * Utiliza Directory API para listar y Groups Settings API para evaluar vulnerabilidades
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-033
 */
class GroupExposureAuditStrategy extends ApiStrategy {
  constructor(authHeader) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-033 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-033",
        valueKey: "valorPrincipal",
        noteKey: "comentario033",
        riskKey: "riesgo033",
        scoreKey: "score033"
      }
    ];

    super("Corporate Groups Exposure Audit", configIDs);
    
    this.authHeader = authHeader;
    // Endpoint primario: Lista todos los grupos del dominio
    this.urlList = "https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer";
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.urlList,
      method: "get",
      muteHttpExceptions: true
    };
  }

  // Traductor estandarizado: Convierte la palabra clave del riesgo a valor numérico
  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN EN CASO DE ERROR DE API PRINCIPAL
    if (json.error) {
      Logger.log(`[ERROR] Group Exposure Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo033: "Medio",
        score033: 2,
        comentario033: "Error de conectividad o permisos insuficientes en las APIs Directory o Groups Settings que impiden listar y evaluar la configuración de membresía de los grupos."
      };
    }

    const grupos = json.groups || [];
    let listaNombresExpuestos = [];

    // for...of para iterar sobre los grupos y mantener el código limpio
    for (const grupo of grupos) {
      // URL de Groups Settings API
      const settingsUrl = `https://www.googleapis.com/groups/v1/groups/${grupo.email}`;
      const options = {
        headers: this.authHeader,
        muteHttpExceptions: true
      };

      try {
        const response = UrlFetchApp.fetch(settingsUrl, options);
        const settings = JSON.parse(response.getContentText());

        // Verificamos si el grupo permite miembros externos
        if (settings.allowExternalMembers === "true") {
          listaNombresExpuestos.push(grupo.email); // Guardamos el email por ser más identificativo
        }
      } catch (e) {
        Logger.log(`[ERROR] Consultando configuración del grupo ${grupo.email}: ${e}`);
      }
    }

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo033, comentario033;

    if (listaNombresExpuestos.length > 0) {
      // Caso 1: Hay grupos vulnerables/expuestos
      respuestaConcreta = "Habilitado";
      riesgo033 = "Alto";
      comentario033 = "Existen listas de distribución o grupos corporativos cuya configuración permite explícitamente la inclusión de miembros externos al dominio de la organización.";
      Logger.log(`[ALERTA RIESGO] Grupos con miembros externos detectados: ${listaNombresExpuestos.join(", ")}`);
    } else {
      // Caso 2: Todos los grupos son internos o no hay grupos
      // Omitimos volcar el JSON para proteger la celda del límite de caracteres
      respuestaConcreta = "Deshabilitado";
      riesgo033 = "Bajo";
      comentario033 = "La totalidad de las listas de distribución analizadas restringen su membresía de forma exclusiva a usuarios internos, o no existen grupos configurados en el dominio.";
      Logger.log(`[LOG] Corporate Groups Audit: Analizados ${grupos.length} grupos. Todos son internos o seguros.`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario033: comentario033,
      riesgo033: riesgo033,
      score033: this.calcularScoreDeRiesgo(riesgo033)
    };
  }
}