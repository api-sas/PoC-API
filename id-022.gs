/**
 * Estrategia para auditar la política del Programa de Protección Avanzada (APP).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-022
 */
class AdvancedProtectionPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-022 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-022", 
        valueKey: "valorPrincipal",
        noteKey: "comentario022",
        riskKey: "riesgo022",
        scoreKey: "score022"
      }
    ];

    super("Advanced Protection Self-Enrollment Audit", configIDs);
    
    // Mantengo tu filtro original intacto
    const filter = `customer=="customers/${customerId}" && setting.type=="settings/security.advanced_protection_program"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
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
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] APP Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo022: "Medio",
        score022: 2,
        comentario022: "Error de lectura o conectividad vía API Cloud Identity que impide auditar técnicamente el estado de la política de auto-enrolamiento del programa."
      };
    }

    const policies = json.policies || [];

    // Filtramos para ver si alguna política permite el auto-enrolamiento
    const selfEnrollmentPolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo (cubriendo las variaciones de la API beta)
        const configNode = policy.setting.advancedProtectionProgram || policy.setting.value || policy.setting;
        
        // Verificamos si el enrolamiento está activo (soportando camelCase y snake_case por seguridad)
        return configNode.enableAdvancedProtectionSelfEnrollment === true || configNode.enable_advanced_protection_self_enrollment === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo022, comentario022;

    if (selfEnrollmentPolicies.length > 0) {
      // Caso 1: La política está configurada y el auto-enrolamiento está activado
      respuestaConcreta = "Habilitado";
      riesgo022 = "Bajo";
      comentario022 = "La política se encuentra configurada y permite a los usuarios inscribirse por sí mismos (auto-enrolamiento) en el Programa de Protección Avanzada.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política de Protección Avanzada configurada
      respuestaConcreta = "Deshabilitado";
      riesgo022 = "Medio";
      comentario022 = "La consola no tiene configurada ninguna directiva general que permita el auto-enrolamiento de los usuarios en el Programa de Protección Avanzada.";

    } else {
      // Caso 3: La política existe pero NO permite el auto-enrolamiento (false). 
      // Volcamos el JSON completo para poder auditar el estado exacto.
      respuestaConcreta = JSON.stringify(json);
      riesgo022 = "Medio";
      comentario022 = "Existe una directiva técnica configurada que bloquea y prohíbe explícitamente a los usuarios la capacidad de inscribirse de forma autónoma en el Programa de Protección Avanzada.";
    }

    // Trazabilidad técnica
    Logger.log(`[LOG] APP Self-Enrollment Audit: Resultado -> ${respuestaConcreta === "Habilitado" ? "Permitido" : (respuestaConcreta === "Deshabilitado" ? "Sin configurar" : "No permitido / Ver JSON")} | Riesgo: ${riesgo022}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario022: comentario022,
      riesgo022: riesgo022,
      score022: this.calcularScoreDeRiesgo(riesgo022)
    };
  }
}