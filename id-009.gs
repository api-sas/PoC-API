/**
 * Estrategia para auditar si se EXIGE la Verificación en 2 pasos (MFA Enforcement).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-009
 */
class TwoStepVerificationEnforcementPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-009 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-009", 
        valueKey: "valorPrincipal",
        noteKey: "comentario009",
        riskKey: "riesgo009",
        scoreKey: "score009"
      }
    ];

    super("2-Step Verification Enforcement Audit", configIDs);
    
    // Filtro con el operador && correcto
    const filter = `customer=="customers/${customerId}" && setting.type=="security.two_step_verification_enforcement"`;
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
      Logger.log(`[ERROR] 2SV Enforcement Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo009: "Medio",
        score009: 2,
        comentario009: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de exigencia (enforcement) de la política."
      };
    }

    const policies = json.policies || [];

    // Filtramos las políticas que ya exigen la verificación hoy mismo
    const enforcedPolicies = policies.filter(policy => {
      if (policy.setting) {
        // La API puede anidar esto bajo twoStepVerificationEnforcement o en value directamente
        const configNode = policy.setting.twoStepVerificationEnforcement || policy.setting.value || policy.setting;
        const enforcedFrom = configNode.enforcedFrom || configNode.enforced_from;

        if (enforcedFrom) {
          const enforcementDate = new Date(enforcedFrom);
          const today = new Date();
          return enforcementDate <= today;
        }
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo009, comentario009;

    if (enforcedPolicies.length > 0) {
      // Caso 1: La política está activa y es obligatoria hoy
      respuestaConcreta = "Habilitado";
      riesgo009 = "Bajo";
      comentario009 = "La política de verificación en dos pasos se encuentra activa y su cumplimiento es estrictamente obligatorio para los usuarios al día de hoy.";
      
    } else if (policies.length === 0) {
      // Caso 2: No hay ninguna política configurada (JSON vacío)
      respuestaConcreta = "Deshabilitado";
      riesgo009 = "Alto";
      comentario009 = "La consola no tiene configurada ninguna directiva para exigir el uso obligatorio de la verificación en dos pasos.";
      
    } else {
      // Caso 3: Hay configuración, pero no es obligatoria o no ha entrado en vigor (Off)
      respuestaConcreta = JSON.stringify(json);
      riesgo009 = "Alto";
      comentario009 = "Existe una directiva configurada, pero el uso de la verificación en dos pasos es opcional o la fecha de obligatoriedad programada se encuentra en el futuro.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] 2SV Enforcement Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo009}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario009: comentario009,
      riesgo009: riesgo009,
      score009: this.calcularScoreDeRiesgo(riesgo009)
    };
  }
}