/**
 * Estrategia para auditar si se permiten Dispositivos de Confianza en MFA.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-011
 */
class TrustedDevice2SVPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-011 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-011", 
        valueKey: "valorPrincipal",
        noteKey: "comentario011",
        riskKey: "riesgo011",
        scoreKey: "score011"
      }
    ];

    super("Trusted Devices for 2SV Audit", configIDs);
    
    // Filtro para la política de cumplimiento de verificación en 2 pasos
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
      Logger.log(`[ERROR] Trusted Device Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo011: "Medio",
        score011: 2,
        comentario011: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de la política de dispositivos de confianza."
      };
    }

    const policies = json.policies || [];

    // Filtramos las políticas para ver si alguna permite explícitamente los dispositivos de confianza
    const trustingDevicePolicies = policies.filter(policy => {
      if (policy.setting) {
        const configNode = policy.setting.twoStepVerificationEnforcement || policy.setting.value || policy.setting;
        // Validamos tanto snake_case como camelCase
        return configNode.allow_trusting_device === true || configNode.allowTrustingDevice === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo011, comentario011;

    if (trustingDevicePolicies.length > 0) {
      // Caso 1: La configuración permite explícitamente confiar en el dispositivo
      respuestaConcreta = "Habilitado";
      riesgo011 = "Medio";
      comentario011 = 'La política configurada permite a los usuarios marcar equipos como "de confianza" para eludir la solicitud del segundo factor de autenticación en inicios de sesión posteriores.';

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay configuraciones
      respuestaConcreta = "Deshabilitado";
      riesgo011 = "Bajo";
      comentario011 = "La consola no tiene configurada ninguna directiva que permita a los usuarios marcar dispositivos como de confianza.";

    } else {
      // Caso 3: Hay políticas pero NO permiten confiar en el dispositivo (volcamos el JSON para revisar)
      respuestaConcreta = JSON.stringify(json);
      riesgo011 = "Bajo";
      comentario011 = "Existe una directiva configurada que prohíbe o bloquea explícitamente la opción de marcar dispositivos como de confianza para omitir el segundo factor.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Trusted Device Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo011}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario011: comentario011,
      riesgo011: riesgo011,
      score011: this.calcularScoreDeRiesgo(riesgo011)
    };
  }
}