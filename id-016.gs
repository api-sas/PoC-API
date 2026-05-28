/**
 * Estrategia para auditar la Recuperación de Cuenta de Superadministrador.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-016
 */
class SuperAdminAccountRecoveryPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-016 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-016", 
        valueKey: "valorPrincipal",
        noteKey: "comentario016",
        riskKey: "riesgo016",
        scoreKey: "score016"
      }
    ];

    super("Super Admin Account Recovery Audit", configIDs);
    
    // Filtro con el operador && para la política de recuperación
    const filter = `customer=="customers/${customerId}" && setting.type=="security.super_admin_account_recovery"`;
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
      Logger.log(`[ERROR] Super Admin Recovery Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo016: "Medio",
        score016: 2,
        comentario016: "Error de lectura vía API Cloud Identity que impide auditar técnicamente el estado de la política de recuperación para cuentas con privilegios de superadministrador."
      };
    }

    const policies = json.policies || [];

    // Filtramos para encontrar políticas que permitan explícitamente la recuperación
    const recoveryEnabledPolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración (cubriendo variaciones de la API beta)
        const configNode = policy.setting.superAdminAccountRecovery || policy.setting.value || policy.setting;
        
        // Verificamos si la recuperación está activa (soportando camelCase y snake_case)
        return configNode.enableAccountRecovery === true || configNode.enable_account_recovery === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo016, comentario016;

    if (recoveryEnabledPolicies.length > 0) {
      // Caso 1: La recuperación de cuenta para superadmins está permitida
      respuestaConcreta = "Habilitado";
      riesgo016 = "Alto";
      comentario016 = "La política permite a los usuarios con privilegios de superadministrador utilizar opciones automatizadas (como correo alternativo o teléfono) para recuperar el acceso a sus cuentas.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política configurada
      respuestaConcreta = "Deshabilitado";
      riesgo016 = "Bajo";
      comentario016 = "No existe configuración en la consola que habilite las opciones automatizadas de recuperación de cuenta para usuarios con rol de superadministrador.";

    } else {
      // Caso 3: La política existe pero la recuperación está denegada (false)
      // Volcamos el JSON para inspección manual técnica
      respuestaConcreta = JSON.stringify(json);
      riesgo016 = "Bajo";
      comentario016 = "Existe una directiva técnica configurada que bloquea y prohíbe explícitamente el uso de opciones automatizadas para la recuperación de cuentas de superadministrador.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Super Admin Recovery Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo016}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario016: comentario016,
      riesgo016: riesgo016,
      score016: this.calcularScoreDeRiesgo(riesgo016)
    };
  }
}