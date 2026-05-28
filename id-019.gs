/**
 * Estrategia para auditar si los desafíos de inicio de sesión exigen el ID de Empleado.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-019
 */
class EmployeeIdLoginChallengePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-019 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-019", 
        valueKey: "valorPrincipal",
        noteKey: "comentario019",
        riskKey: "riesgo019",
        scoreKey: "score019"
      }
    ];

    super("Employee ID Login Challenge Audit", configIDs);
    
    // Usamos el filtro con && apuntando a login_challenges
    const filter = `customer=="customers/${customerId}" && setting.type=="security.login_challenges"`;
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
      Logger.log(`[ERROR] Employee ID Challenge Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo019: "Medio",
        score019: 2,
        comentario019: "Error de conectividad o lectura vía API Cloud Identity que impide validar técnicamente el estado de la política de desafío mediante ID de empleado."
      };
    }

    const policies = json.policies || [];

    // Filtramos para aislar exactamente las reglas que tienen el desafío de ID habilitado
    const activeChallengePolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración
        const configNode = policy.setting.loginChallenges || policy.setting.value || policy.setting;
        
        // Verificamos si el desafío de ID de empleado está habilitado (camelCase o snake_case)
        return configNode.enableEmployeeIdChallenge === true || configNode.enable_employee_id_challenge === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo019, comentario019;

    if (activeChallengePolicies.length > 0) {
      // Caso 1: El desafío por ID de empleado está configurado y habilitado
      respuestaConcreta = "Habilitado";
      riesgo019 = "Bajo";
      comentario019 = "La política configurada exige que los usuarios ingresen su número de identificación de empleado (Employee ID) como medida de verificación adicional ante un intento de inicio de sesión clasificado como sospechoso.";
      
    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política de desafíos configurada
      respuestaConcreta = "Deshabilitado";
      riesgo019 = "Medio";
      comentario019 = "La consola no tiene configurada ninguna directiva general que habilite o exija el identificador de empleado como mecanismo de desafío de inicio de sesión.";
      
    } else {
      // Caso 3: La política existe pero está apagada (false).
      // Volcamos el JSON completo para validar la configuración en el Excel.
      respuestaConcreta = JSON.stringify(json);
      riesgo019 = "Medio";
      comentario019 = "Existe una directiva de desafíos de inicio de sesión configurada, pero la exigencia del identificador de empleado se encuentra explícitamente desactivada o denegada.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Employee ID Challenge Audit: Resultado -> ${respuestaConcreta === "Habilitado" ? "Activado" : (respuestaConcreta === "Deshabilitado" ? "Sin configurar" : "Apagado / Ver JSON")} | Riesgo: ${riesgo019}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario019: comentario019,
      riesgo019: riesgo019,
      score019: this.calcularScoreDeRiesgo(riesgo019)
    };
  }
}