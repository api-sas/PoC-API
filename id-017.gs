/**
 * Estrategia para auditar la Recuperación de Cuenta para Usuarios Regulares (No administradores).
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-017
 */
class UserAccountRecoveryPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-017 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-017",
        valueKey: "valorPrincipal",
        noteKey: "comentario017",
        riskKey: "riesgo017",
        scoreKey: "score017"
      }
    ];

    super("User Account Recovery Audit", configIDs);
    
    // Filtro con el operador && para la política de recuperación de usuarios normales
    const filter = `customer=="customers/${customerId}" && setting.type=="security.user_account_recovery"`;
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
      Logger.log(`[ERROR] User Recovery Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo017: "Medio",
        score017: 2,
        comentario017: "Error de lectura vía API Cloud Identity que impide auditar técnicamente el estado de la política de recuperación de contraseñas para cuentas de usuarios regulares."
      };
    }

    const policies = json.policies || [];

    // Filtramos para aislar exactamente las reglas que tienen la recuperación habilitada
    const recoveryEnabledPolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración
        const configNode = policy.setting.userAccountRecovery || policy.setting.value || policy.setting;
        
        // Verificamos el acceso (soportando camelCase y snake_case)
        return configNode.enableAccountRecovery === true || configNode.enable_account_recovery === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo017, comentario017;

    if (recoveryEnabledPolicies.length > 0) {
      // Caso 1: La recuperación autónoma para usuarios regulares está permitida
      respuestaConcreta = "Habilitado";
      riesgo017 = "Medio";
      comentario017 = "La política permite a los usuarios sin privilegios administrativos utilizar opciones de autoservicio (como correo alternativo o SMS) para recuperar contraseñas olvidadas de forma autónoma.";

    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política configurada
      respuestaConcreta = "Deshabilitado";
      riesgo017 = "Bajo";
      comentario017 = "La consola no tiene configurada ninguna directiva que habilite las opciones automatizadas de recuperación de cuenta por autoservicio para usuarios regulares.";

    } else {
      // Caso 3: La política existe pero la recuperación está denegada (false)
      // Volcamos el JSON para inspección manual técnica
      respuestaConcreta = JSON.stringify(json);
      riesgo017 = "Bajo";
      comentario017 = "Existe una directiva técnica configurada que prohíbe explícitamente a los usuarios regulares el uso de mecanismos automatizados para el restablecimiento autónomo de sus contraseñas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] User Recovery Audit: Resultado final -> ${respuestaConcreta === "Habilitado" ? "Permitida" : (respuestaConcreta === "Deshabilitado" ? "Sin configurar" : "Denegada / Ver JSON")} | Riesgo: ${riesgo017}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario017: comentario017,
      riesgo017: riesgo017,
      score017: this.calcularScoreDeRiesgo(riesgo017)
    };
  }
}