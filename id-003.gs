/**
 * Estrategia de Políticas de Contraseña (En Memoria).
 * Hereda de ApiStrategy para usar writeToSheet automáticamente.
 */
class StrongPasswordPolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { 
        id: "ID-003", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario003", 
        riskKey: "riesgo003", 
        scoreKey: "score003" 
      }
    ];
    
    super("Strong Password Policy Audit", configIDs);
    
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
  }

  evaluateInMemory(globalContext) {
    const { census, policies } = globalContext;

    if (!census || !policies) {
      return this._buildErrorResponse("Falta el contexto global (censo o políticas).");
    }
    
    const passwordPolicies = policies.filter(p => p.setting && p.setting.type === "security.password");
    
    // La política raíz es la que no tiene filtros de "entity." (Aplica a todo el customer)
    const rootPolicy = passwordPolicies.find(p => !p.query || !p.query.includes("entity."));
    
    let rootStrength = "Desconocido";
    let isRootEnforced = false;
    // https://docs.cloud.google.com/identity/docs/concepts/supported-policy-api-settings?hl=es-419&authuser=3#security_settings
    if (rootPolicy && rootPolicy.setting && rootPolicy.setting.password) {
      rootStrength = rootPolicy.setting.password.allowedStrength || "Desconocido";
      isRootEnforced = rootPolicy.setting.password.enforceRequirementsAtLogin === true;
    }

    // Definimos el valor a imprimir basado estrictamente en lo que dice la raíz
    let estadoPrincipal = rootStrength === "STRONG" ? "Fuerte" : "Débil";
    if (!isRootEnforced) estadoPrincipal += "- Inhabilitado";
    Logger.log(`[ID-003] Respuesta de la API (Raíz): Fuerza criptográfica='${rootStrength}', Forzado en Login=${isRootEnforced}`);

    // 2. Lógica de porcentajes 
    let usuariosCumplen = 0;
    let usuariosNoCumplen = 0;
    
    for (const user of census) {
      const aplicables = passwordPolicies.filter(p => CELParserEngine.evaluate(p.query, user));
      const politicaGanadora = PolicyReducerFactory.reduce(aplicables, "security.password");

      if (this._isPolicyStrong(politicaGanadora)) {
        usuariosCumplen++;
      } else {
        usuariosNoCumplen++;
      }
    }

    const totalUsuarios = usuariosCumplen + usuariosNoCumplen;
    const porcentajeCumplimiento = totalUsuarios > 0 ? Math.round((usuariosCumplen / totalUsuarios) * 100) : 0;
    
    let riesgo = "Alto";
    let comentario = `Solo el ${porcentajeCumplimiento}% de los usuarios tienen exigencia de contraseñas fuertes (STRONG).`;

    if (porcentajeCumplimiento === 100) {
      riesgo = "Bajo";
      comentario = "El 100% de la organización está gobernada por políticas de contraseñas seguras.";
    } else if (porcentajeCumplimiento >= 50) {
      riesgo = "Medio";
    }
    Logger.log(`[ID-003] Se prepararon los datos en memoria para imprimir en la celda y actualizar el semáforo.`);

    return {
      name: this.name,
      // Cambiado: Ahora imprime la configuración base (ej. "Fuerte") en lugar del porcentaje
      valorPrincipal: estadoPrincipal, 
      comentario003: comentario,
      riesgo003: riesgo,
      score003: this.calcularScoreDeRiesgo(riesgo)
    };
  }

  _isPolicyStrong(policy) {
    if (!policy || !policy.setting || !policy.setting.password) return false;
    const pwd = policy.setting.password;
    return pwd.allowedStrength === "STRONG" && pwd.enforceRequirementsAtLogin === true;
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  _buildErrorResponse(msg) {
    return {
      name: this.name,
      valorPrincipal: "ERROR EN MEMORIA",
      riesgo003: "Medio",
      score003: 2,
      comentario003: msg
    };
  }
}