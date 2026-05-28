/**
 * Estrategia para auditar si se EXIGE la Verificación en 2 pasos para Administradores/OU específica.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-010
 */
class AdminTwoStepVerificationEnforcementStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-010 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-010", 
        valueKey: "valorPrincipal",
        noteKey: "comentario010",
        riskKey: "riesgo010",
        scoreKey: "score010"
      }
    ];

    super("Admin/OU 2-Step Verification Enforcement Audit", configIDs);
    
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
      Logger.log(`[ERROR] Admin 2SV Enforcement Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo010: "Medio",
        score010: 2,
        comentario010: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de exigencia (enforcement) de la política para los administradores."
      };
    }

    const policies = json.policies || [];

    // Filtramos las políticas que exigen 2SV hoy mismo
    const enforcedPolicies = policies.filter(policy => {
      if (policy.setting) {
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
    let riesgo010, comentario010;

    if (enforcedPolicies.length > 0) {
      // Caso 1: Todo correcto y activo
      respuestaConcreta = "Habilitado";
      riesgo010 = "Bajo";
      comentario010 = "La política de verificación en dos pasos se encuentra activa y su cumplimiento es estrictamente obligatorio en la fecha actual para el grupo o unidad organizativa de administradores.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON vino vacío o sin políticas
      respuestaConcreta = "Deshabilitado";
      riesgo010 = "Alto";
      comentario010 = "La consola no tiene configurada ninguna directiva para exigir el uso obligatorio de la verificación en dos pasos en las cuentas con privilegios administrativos.";

    } else {
      // Caso 3: Hay configuración, pero no cumple el criterio (Off), volcamos JSON para inspección
      respuestaConcreta = JSON.stringify(json);
      riesgo010 = "Alto";
      comentario010 = "Existe una directiva configurada para las cuentas administrativas, pero el uso de la verificación en dos pasos es opcional o la fecha de obligatoriedad se encuentra programada en el futuro.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Admin 2SV Enforcement Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo010}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario010: comentario010,
      riesgo010: riesgo010,
      score010: this.calcularScoreDeRiesgo(riesgo010)
    };
  }
}