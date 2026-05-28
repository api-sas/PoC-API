/**
 * Estrategia para auditar el Período de Gracia de la Verificación en 2 pasos.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-013
 */
class GracePeriod2SVPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: matriz con el ID-013 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-013", 
        valueKey: "valorPrincipal",
        noteKey: "comentario013",
        riskKey: "riesgo013",
        scoreKey: "score013"
      }
    ];

    super("2SV Grace Period Audit", configIDs);
    
    // Endpoint de lista con el filtro &&
    const filter = `customer=="customers/${customerId}" && setting.type=="security.two_step_verification_grace_period"`;
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
      Logger.log(`[ERROR] Grace Period Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo013: "Medio",
        score013: 2,
        comentario013: "Error de lectura vía API Cloud Identity que impide validar técnicamente el estado de la política de período de gracia."
      };
    }

    const policies = json.policies || [];
    let segundos = 0;

    // Filtramos para encontrar políticas donde el período de gracia sea mayor a 0
    const activeGracePeriodPolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración
        const configNode = policy.setting.twoStepVerificationGracePeriod || policy.setting.value || policy.setting;
        const durationStr = configNode.duration || configNode.grace_period;
        
        if (durationStr) {
          // El formato es "12345s", quitamos la 's' y convertimos a número entero
          const parsedSegundos = parseInt(durationStr.toString().replace('s', ''));
          if (parsedSegundos > 0) {
            segundos = parsedSegundos; // Lo guardamos para el Logger
            return true;
          }
        }
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo013, comentario013;

    if (activeGracePeriodPolicies.length > 0) {
      // Caso 1: Hay un período de gracia configurado y es mayor a 0
      respuestaConcreta = "Habilitado";
      riesgo013 = "Medio";
      comentario013 = "La política se encuentra configurada otorgando un período de tiempo mayor a cero en el cual los usuarios pueden eludir temporalmente la exigencia de la verificación en dos pasos.";
      
      // Cálculos visuales exclusivos para el log de auditoría de la consola
      let duracionTexto = segundos >= 86400 
        ? `${(segundos / 86400).toFixed(1)} días` 
        : `${(segundos / 3600).toFixed(1)} horas`;
      Logger.log(`[LOG] Grace Period Audit: Período de gracia detectado de ${duracionTexto}.`);
      
    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política configurada en absoluto
      respuestaConcreta = "Deshabilitado";
      riesgo013 = "Bajo";
      comentario013 = "La consola no tiene configurada ninguna directiva referente a un período de gracia; no se otorgan ventanas temporales de evasión por defecto.";
      Logger.log(`[LOG] Grace Period Audit: No se encontró política de período de gracia (vacío).`);
      
    } else {
      // Caso 3: La política existe pero el tiempo es 0 (estricto sin gracia). 
      // Volcamos el JSON completo para validar la configuración exacta.
      respuestaConcreta = JSON.stringify(json);
      riesgo013 = "Bajo";
      comentario013 = "Existe una directiva configurada explícitamente con un valor de cero segundos, indicando un cumplimiento estricto e inmediato sin ventana de gracia.";
      Logger.log(`[LOG] Grace Period Audit: Configurado en 0 (sin período de gracia). Volcando JSON.`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario013: comentario013,
      riesgo013: riesgo013,
      score013: this.calcularScoreDeRiesgo(riesgo013)
    };
  }
}