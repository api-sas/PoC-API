/**
 * Estrategia para auditar los Métodos Permitidos para la Verificación en 2 pasos.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-012
 */
class Allowed2SVMethodsPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-012 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-012", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario012",
        riskKey: "riesgo012",
        scoreKey: "score012"
      }
    ];

    super("Allowed 2SV Methods Audit", configIDs);
    
    // Filtro con && y el setting type específico para los factores de MFA
    const filter = `customer=="customers/${customerId}" && setting.type=="security.two_step_verification_enforcement_factor"`;
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
      Logger.log(`[ERROR] Allowed 2SV Methods Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo012: "Medio",
        score012: 2,
        comentario012: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de las restricciones de los métodos de verificación en dos pasos."
      };
    }

    const policies = json.policies || [];

    // Filtramos las políticas para ver si alguna permite explícitamente métodos débiles (ANY o ALL)
    const weakMethodsPolicies = policies.filter(policy => {
      if (policy.setting) {
        const configNode = policy.setting.twoStepVerificationEnforcementFactor || policy.setting.value || policy.setting;
        
        // Extraemos el factor permitido (soportando snake y camel case)
        const allowedFactorSet = configNode.allowed_sign_in_factor_set || configNode.allowedSignInFactorSet;
        
        // Retornamos true si permite métodos vulnerables
        return allowedFactorSet === "ANY" || allowedFactorSet === "ALL";
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo012, comentario012;

    if (weakMethodsPolicies.length > 0) {
      // Caso 1: La configuración existe y permite métodos débiles (SMS, llamadas, etc.)
      respuestaConcreta = "Habilitado";
      riesgo012 = "Medio";
      comentario012 = "La política configurada permite explícitamente el uso de cualquier método de verificación en dos pasos (ANY o ALL), incluyendo factores vulnerables a intercepción como SMS o llamadas de voz.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política configurada en absoluto
      respuestaConcreta = "Deshabilitado";
      riesgo012 = "Alto";
      comentario012 = "La consola no tiene configurada ninguna directiva que restrinja o controle los métodos permitidos para el segundo factor de autenticación.";

    } else {
      // Caso 3: Hay política, pero NO es "ANY" ni "ALL". 
      // Es una política restrictiva y segura. Volcamos el JSON para poder revisar qué configuró el admin.
      respuestaConcreta = JSON.stringify(json);
      riesgo012 = "Bajo";
      comentario012 = "Existe una política configurada que restringe los métodos de verificación en dos pasos, bloqueando opciones generales débiles y forzando el uso de factores específicos más seguros.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Allowed 2SV Methods Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo012}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario012: comentario012,
      riesgo012: riesgo012,
      score012: this.calcularScoreDeRiesgo(riesgo012)
    };
  }
}