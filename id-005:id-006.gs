/**
 * Estrategia para auditar tokens OAuth y aplicaciones de terceros conectadas.
 * Utiliza la Admin SDK: Directory API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-005 e ID-006
 */
class AuditTokens extends ApiStrategy {
  constructor(userKey = "me") { 
    // 1. Nueva arquitectura: Definimos la matriz para inyectar en DOS filas distintas
    const configIDs = [
      { 
        id: "ID-005", 
        valueKey: "valorPrincipal",
        noteKey: "comentario005",
        riskKey: "riesgo005",
        scoreKey: "score005"
      },
      { 
        id: "ID-006",
        valueKey: "valorSecundario",
        noteKey: "comentario006",
        riskKey: "riesgo006",
        scoreKey: "score006"
      }
    ];

    super("OAuth Tokens Audit", configIDs);
    this.userKey = userKey;
    this.url = `https://admin.googleapis.com/admin/directory/v1/users/${this.userKey}/tokens`;
    this.category = "Identidad y autenticación";
  }

  getRequestConfig() {
    return {
      url: this.url,
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
    // 1. EVALUACIÓN EN CASO DE ERROR DE API (Aplica para ambos IDs)
    if (json.error) {
       Logger.log(`[ERROR] OAuth Tokens Audit: ${json.error.message || JSON.stringify(json.error)}`);
       return { 
         name: this.name, 
         raw: json,

         // ID-005 Error
         valorPrincipal: "ERROR",
         riesgo005: "Medio",
         score005: 2,
         comentario005: "Error de conectividad o permisos con la API Directory que impide auditar la conexión de aplicaciones.",
         
         // ID-006 Error
         valorSecundario: "ERROR",
         riesgo006: "Medio",
         score006: 2,
         comentario006: "Error de lectura vía API Directory que impide calcular la sumatoria de aplicaciones conectadas."
       };
    }

    // 2. PARSEO DE DATOS EXITOSOS
    const tokens = json.items || [];
    const totalTokens = tokens.length;

    let respuestaConcreta;
    let riesgo005, comentario005;
    let riesgo006, comentario006;

    // 3. APLICACIÓN DE REGLAS DE NEGOCIO (Hardcodeadas desde toadd.csv)
    if (totalTokens > 0) {
      // Caso 1: Hay aplicaciones de terceros conectadas
      respuestaConcreta = "Habilitado";

      // Reglas ID-005
      riesgo005 = "Alto";
      comentario005 = "Existen tokens OAuth emitidos en la cuenta, lo que indica que se permite el acceso a aplicaciones de terceros.";

      // Reglas ID-006
      riesgo006 = "Medio";
      comentario006 = "Indica el número exacto de aplicaciones de terceros que actualmente poseen tokens OAuth activos vinculados a la cuenta.";

    } else {
      // Caso 2: No hay tokens conectados (totalTokens === 0)
      respuestaConcreta = "Deshabilitado";

      // Reglas ID-005
      riesgo005 = "Bajo";
      comentario005 = "No existen tokens OAuth emitidos; ninguna aplicación de terceros tiene acceso a la información de la cuenta.";

      // Reglas ID-006
      riesgo006 = "Bajo";
      comentario006 = "El sistema contabiliza un total de cero aplicaciones de terceros autorizadas en la cuenta.";
    }

    Logger.log(`[LOG] OAuth Tokens Audit: Se detectaron ${totalTokens} aplicaciones/tokens asociados. Resultado -> ${respuestaConcreta}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,

      // Mapeo ID-005 (Estado booleano general)
      valorPrincipal: respuestaConcreta, 
      comentario005: comentario005,
      riesgo005: riesgo005,
      score005: this.calcularScoreDeRiesgo(riesgo005),

      // Mapeo ID-006 (Valor entero del conteo)
      valorSecundario: totalTokens,      
      comentario006: comentario006,
      riesgo006: riesgo006,
      score006: this.calcularScoreDeRiesgo(riesgo006)
    };
  }
}