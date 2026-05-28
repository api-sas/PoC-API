/**
 * Estrategia para auditar si se permite la inscripción en la Verificación en 2 pasos (MFA).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-007
 */
class TwoStepVerificationEnrollmentPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-007 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-007", 
        valueKey: "valorPrincipal",
        noteKey: "comentario007",
        riskKey: "riesgo007",
        scoreKey: "score007"
      }
    ];

    super("2-Step Verification Enrollment Audit", configIDs);
    
    // Aplicamos el filtro con el operador &&
    const filter = `customer=="customers/${customerId}" && setting.type=="security.two_step_verification_enrollment"`;
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
      Logger.log(`[ERROR] 2SV Enrollment Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo007: "Medio",
        score007: 2,
        comentario007: "Error de lectura vía API Cloud Identity que impide validar el estado técnico de la política de enrolamiento de la verificación en dos pasos."
      };
    }

    const policies = json.policies || [];

    // Filtramos para encontrar políticas que permitan explícitamente el enrolamiento
    const allowEnrollmentPolicies = policies.filter(policy => {
      if (policy.setting) {
        const configNode = policy.setting.twoStepVerificationEnrollment || policy.setting.value || policy.setting;
        return configNode.allow_enrollment === true || configNode.allowEnrollment === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo007, comentario007;

    if (allowEnrollmentPolicies.length > 0) {
      // Caso 1: Los usuarios pueden activar MFA por sí mismos
      respuestaConcreta = "Habilitado";
      riesgo007 = "Bajo";
      comentario007 = "La política configurada en el dominio permite a los usuarios inscribirse y activar la verificación en dos pasos en sus cuentas.";
      
    } else if (policies.length === 0) {
      // Caso 2: El JSON vino vacío (sin configuración)
      respuestaConcreta = "Deshabilitado";
      riesgo007 = "Alto";
      comentario007 = "La consola no tiene configurada ninguna directiva para el enrolamiento de la verificación en dos pasos.";
      
    } else {
      // Caso 3: La política existe pero está bloqueando el enrolamiento (false)
      // Volcamos el JSON para inspección manual
      respuestaConcreta = JSON.stringify(json);
      riesgo007 = "Alto";
      comentario007 = "La política existe y está configurada explícitamente para bloquear o impedir que los usuarios activen la verificación en dos pasos.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] 2SV Enrollment Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo007}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario007: comentario007,
      riesgo007: riesgo007,
      score007: this.calcularScoreDeRiesgo(riesgo007)
    };
  }
}