/**
 * Estrategia híbrida para auditar las políticas de contraseñas seguras (ID-003).
 * Cumple con arquitectura v1, reducción de conflictos (Max Reducer) y 
 * bifurcación topológica mediante análisis de SSO.
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
    this.category = "Authentication"; 
    this.customerId = customerId || "my_customer";

    // 1. MIGRACIÓN A V1 Y FILTRO CEL
    const filter = `customer=="customers/${this.customerId}" && setting.type=="security.password"`;
    this.url = `https://cloudidentity.googleapis.com/v1/policies?filter=${encodeURIComponent(filter)}`;
  }

  getRequestConfig() {
    return {
      url: this.url,
      method: "get",
      muteHttpExceptions: true
    };
  }

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    return null;
  }

  // Mantenemos la telemetría empírica viva como proxy adicional de seguridad
  _getEmpiricalTelemetry() {
    const date = new Date();
    date.setDate(date.getDate() - 3);
    const reportDate = Utilities.formatDate(date, Session.getScriptTimeZone(), 'yyyy-MM-dd');
    
    let metrics = { lengthUnknown: 0, strengthWeak: 0, strengthStrong: 0, status: "ERROR" };
    try {
      const response = AdminReports.CustomerUsageReports.get(reportDate);
      if (response && response.usageReports && response.usageReports.length > 0) {
        const parameters = response.usageReports[0].parameters;
        for (const param of parameters) {
          if (param.name === 'accounts:num_users_password_length_unknown') {
            metrics.lengthUnknown = parseInt(param.intValue, 10);
          } else if (param.name === 'accounts:num_users_password_strength_weak') {
            metrics.strengthWeak = parseInt(param.intValue, 10);
          } else if (param.name === 'accounts:num_users_password_strength_strong') {
            metrics.strengthStrong = parseInt(param.intValue, 10);
          }
        }
        metrics.status = "OK";
      }
    } catch (e) {
      Logger.log(`[AVISO] Telemetría empírica (Reports API) no disponible: ${e.message}`);
    }
    return metrics;
  }

  parseResponse(json) {
    Logger.log(JSON.stringify(json));
    // 1. MANEJO DE ERRORES DE RED (Cloud Identity)
    if (json.error) {
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR DE API", 
        riesgo003: "Medio", 
        score003: 2, 
        comentario003: `Fallo crítico de Cloud Identity: ${json.error.message || "Error desconocido"}` 
      };
    }

    // 2. PAGINACIÓN OBLIGATORIA DE POLÍTICAS
    let policies = json.policies || [];
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada en políticas. Obteniendo páginas restantes...");
      const allPolicies = this.fetchPaginated(this.url, "policies");
      if (allPolicies) policies = allPolicies;
    }

    // 3. EMULACIÓN DEL REDUCTOR MAX (Resolución de Conflictos)
    // Buscamos la política que tenga el mayor peso operativo (sortOrder)
    let activePolicy = null;
    if (policies.length > 0) {
      activePolicy = policies.reduce((prev, current) => {
        // En Cloud Identity v1, el weight/sortOrder define la precedencia. 
        // Si no existe, se asume 0 para no romper la reducción lógica.
        const prevOrder = parseInt(prev.sortOrder || 0);
        const currOrder = parseInt(current.sortOrder || 0);
        return (prevOrder >= currOrder) ? prev : current;
      });
    }

    // 4. EXTRACCIÓN DE ATRIBUTOS CRIPTOGRÁFICOS
    let strengthOficial = "Desconocido";
    let isEnforced = false;
    let allowReuse = "Desconocido";

    if (activePolicy && activePolicy.setting && activePolicy.setting.password) {
      const passNode = activePolicy.setting.password;
      strengthOficial = passNode.allowedStrength || "Desconocido";
      isEnforced = passNode.enforceRequirementsAtLogin === true;
      allowReuse = passNode.allowReuse === true;
    }

    Logger.log(`[LOG ID-003] Reductor Max seleccionó política: Fuerza=${strengthOficial}, Enforced=${isEnforced}, allowReuse=${allowReuse}`);

    // 5. BIFURCACIÓN TOPOLÓGICA (Contexto SSO Activo)
    // Evaluamos directamente inboundSsoAssignments para verificar si las políticas de Google están siendo puenteadas
    Logger.log("[INFO ID-003] Verificando contexto SSO topológico...");
    const urlAssignments = `https://cloudidentity.googleapis.com/v1/inboundSsoAssignments?filter=${encodeURIComponent('customer=="customers/' + this.customerId + '"')}`;
    const ssoAssignments = this.fetchPaginated(urlAssignments, "inboundSsoAssignments") || [];
    const isSsoActive = ssoAssignments.some(a => a.ssoMode === "SAML_SSO" || a.ssoMode === "OIDC_SSO");

    // Extraemos la telemetría empírica como mecanismo secundario de confirmación
    const telemetry = this._getEmpiricalTelemetry();

    // 6. LÓGICA DE NEGOCIO MATRICIAL
    let riesgo003, comentario003;

    if (isSsoActive) {
      // Escenario A: Dominio federado. La política de Google es irrelevante.
      riesgo003 = "Medio"; // Neutralizamos el riesgo local para evitar falsos positivos
      comentario003 = "POLÍTICA INACTIVA (SSO DETECTADO): La organización utiliza un Proveedor de Identidad (IdP) externo activo. Las políticas de contraseña de Google Workspace son latentes y no se aplican. La dureza criptográfica DEBE auditarse en el IdP de terceros.";
    } 
    else if (policies.length === 0 || strengthOficial === "Desconocido") {
      // Escenario B: Falsos Positivos de Valores Vacíos (Infraestructura heredada)
      riesgo003 = "Medio";
      comentario003 = "AUDITORÍA INCONCLUSIVA: La API no devuelve parámetros explícitos (arquitectura heredada) y no se detectó configuración nativa. Requiere revisión empírica o manual.";
    } 
    else if (strengthOficial === "STRONG" && isEnforced === true && allowReuse === false) {
      // Escenario C: Configuración Óptima exigida por el requerimiento
      riesgo003 = "Bajo";
      comentario003 = `CUMPLIMIENTO: Política nativa óptima. Se exige obligatoriamente fuerza criptográfica (STRONG) en el login, y el reciclaje está bloqueado.`;
    } 
    else {
      // Escenario D: Vulnerable (No se exige STRONG o no es forzoso en el login)
      riesgo003 = "Alto";
      let deficiencias = [];
      if (strengthOficial !== "STRONG") deficiencias.push(`Fuerza permitida: ${strengthOficial}`);
      if (!isEnforced) deficiencias.push("No se forza el requerimiento en el Login");
      if (allowReuse) deficiencias.push("Permite reciclaje de contraseñas");

      comentario003 = `VULNERABILIDAD CONFIGURADA: El entorno nativo no exige una contraseña segura y estricta. Deficiencias: ${deficiencias.join(" | ")}.`;
    }

    // 7. RETORNO PARA LA FACADE Y LA CLASE PADRE
    return {
      name: this.name,
      raw: {
        policySelected: activePolicy,
        telemetryData: telemetry,
        ssoAssignments: ssoAssignments
      },
      valorPrincipal: strengthOficial !== "Desconocido" ? `${strengthOficial} (Enforced: ${isEnforced})` : "Heredado",
      comentario003: comentario003.trim(),
      riesgo003: riesgo003,
      score003: this.calcularScoreDeRiesgo(riesgo003)
    };
  }
}