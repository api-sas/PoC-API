/**
 * Estrategia para auditar si se permite el uso de Códigos de Seguridad (Backup Codes).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-014
 */
class TwoStepVerificationSignInCodePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-014 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-014", 
        valueKey: "valorPrincipal",
        noteKey: "comentario014",
        riskKey: "riesgo014",
        scoreKey: "score014"
      }
    ];

    super("2SV Backup Codes Audit", configIDs);
    
    // Filtro con el operador && para evitar el error 7003
    const filter = `customer=="customers/${customerId}" && setting.type=="security.two_step_verification_sign_in_code"`;
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
      Logger.log(`[ERROR] 2SV Backup Codes Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo014: "Medio",
        score014: 2,
        comentario014: "Error de lectura vía API Cloud Identity que impide validar técnicamente si el uso de códigos de seguridad se encuentra autorizado o bloqueado."
      };
    }

    const policies = json.policies || [];

    // Filtramos las políticas para ver si alguna permite explícitamente los códigos de respaldo
    const backupCodePolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración
        const configNode = policy.setting.twoStepVerificationSignInCode || policy.setting.value || policy.setting;
        
        // Verificamos el acceso (soportando camelCase y snake_case)
        return configNode.allowSignInCode === true || configNode.allow_sign_in_code === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo014, comentario014;

    if (backupCodePolicies.length > 0) {
      // Caso 1: La configuración permite generar y usar códigos de respaldo
      respuestaConcreta = "Habilitado";
      riesgo014 = "Medio";
      comentario014 = "La política configurada en el dominio autoriza a los usuarios a generar y utilizar códigos de seguridad estáticos de un solo uso (códigos de respaldo) como método válido para eludir la autenticación en dos pasos habitual.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay configuraciones al respecto
      respuestaConcreta = "Deshabilitado";
      riesgo014 = "Bajo";
      comentario014 = "La consola de administración no cuenta con ninguna directiva configurada que permita la generación o uso de códigos estáticos de respaldo.";

    } else {
      // Caso 3: Hay políticas, pero NO permiten el uso de códigos (está en false). 
      // Volcamos el JSON completo para permitir su revisión técnica.
      respuestaConcreta = JSON.stringify(json);
      riesgo014 = "Bajo";
      comentario014 = "Existe una directiva técnica configurada que bloquea y prohíbe explícitamente a los usuarios la capacidad de utilizar códigos de seguridad estáticos para acceder a sus cuentas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] 2SV Backup Codes Audit: Resultado -> ${respuestaConcreta === "Habilitado" ? "Permitido" : (respuestaConcreta === "Deshabilitado" ? "Sin configurar" : "No permitido / Ver JSON")} | Riesgo: ${riesgo014}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario014: comentario014,
      riesgo014: riesgo014,
      score014: this.calcularScoreDeRiesgo(riesgo014)
    };
  }
}