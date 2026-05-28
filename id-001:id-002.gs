/**
 * Estrategia unificada para auditar la configuración de Single Sign-On (SSO / IdP).
 * Cumple con la arquitectura de producción v1 al cruzar perfiles estáticos con asignaciones vivas.
 */
class SsoAuditStrategy extends ApiStrategy {
  constructor(customerId) {
    const configIDs = [
      { id: "ID-001", valueKey: "valorPrincipal", noteKey: "comentario001", riskKey: "riesgo001", scoreKey: "score001" },
      { id: "ID-002", valueKey: "valorSecundario", noteKey: "comentario002", riskKey: "riesgo002", scoreKey: "score002" }
    ];
   
    super("SSO Identity Providers", configIDs);
    this.customerId = customerId || "my_customer";
    this.category = "Identidad y autenticación";
    
    // MIGRACIÓN A V1
    const filter = `customer=="customers/${this.customerId}"`;
    this.url = `https://cloudidentity.googleapis.com/v1/inboundSamlSsoProfiles?filter=${encodeURIComponent(filter)}`;
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

  parseResponse(json) {
    // 1. MANEJO DEFENSIVO DE ERRORES DE RED
    Logger.log(`[SSO] Respuesta JSON recibida: ${JSON.stringify(json)}`);
    if (json.error) {
      Logger.log(`[ERROR API] SsoAuditStrategy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, raw: json,
        valorPrincipal: "ERROR_API", riesgo001: "Medio", score001: 2,
        comentario001: `Fallo ID-001: ${json.error.message}`,
        valorSecundario: "ERROR_API", riesgo002: "Medio", score002: 2,
        comentario002: "Imposible calcular la proporción debido al error de red previo."
      };
    }
    
    // 2. ITEM 1: PERFILES SSO (Denominador)
    let perfilesSso = json.inboundSamlSsoProfiles || [];
    
    // Re-hidratación vía paginador (Usa las cabeceras anti-caché heredadas de la Facade)
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada. Extrayendo el resto de perfiles SSO...");
      const todosLosPerfiles = this.fetchPaginated(this.url, "inboundSamlSsoProfiles");
      if (todosLosPerfiles) perfilesSso = todosLosPerfiles;
    }

    const totalPerfilesDeclarados = perfilesSso.length;

    // === MANEJO DE JSON VACÍO Y VALIDACIÓN MULTIPARTITA ===
    if (totalPerfilesDeclarados === 0) {
      Logger.log("[INFO] La API retornó un inventario vacío de perfiles SSO.");
      return {
        name: this.name,
        raw: json,
        valorPrincipal: "Ninguno configurado",
        riesgo001: "Alto",
        score001: 1,
        // Advertencia sobre operaciones asíncronas no aprobadas
        comentario001: "La organización no cuenta con perfiles SSO activos o su creación se encuentra en estado 'awaiting-multi-party-approval'. Si aplicó cambios recientes en la consola, requieren de la aprobación de un segundo administrador para reflejarse en el backend.",
        valorSecundario: "0%",
        riesgo002: "Alto",
        score002: 1,
        comentario002: "Ningún perfil de autenticación en la organización está haciendo uso de la configuración SSO."
      };
    }

    // Preparamos respuesta limpia ID-001
    let listaPerfilesAuditoria = perfilesSso.map(p => ({ displayName: p.displayName || "Sin nombre", name: p.name }));
    const respuestaConcretaID001 = JSON.stringify(listaPerfilesAuditoria);
    
    // 3. ITEM 2: ASIGNACIONES VIVAS (Numerador)
    Logger.log("[INFO] Consultando asignaciones SSO para validar uso criptográfico activo...");
    const filterAssignments = `customer=="customers/${this.customerId}"`;
    const urlAssignments = `https://cloudidentity.googleapis.com/v1/inboundSsoAssignments?filter=${encodeURIComponent(filterAssignments)}`;
    
    const asignacionesVivas = this.fetchPaginated(urlAssignments, "inboundSsoAssignments") || [];

    let perfilesActivosUnicos = new Set();
    
    for (const asignacion of asignacionesVivas) {
      const ssoMode = asignacion.ssoMode;
      // Validamos redirección activa
      if (ssoMode === "SAML_SSO" || ssoMode === "OIDC_SSO") {
        const perfilVinculado = asignacion.samlSsoProfile || asignacion.ssoProfile;
        if (perfilVinculado) {
          perfilesActivosUnicos.add(perfilVinculado);
        }
      }
    }

    const totalActivos = perfilesActivosUnicos.size;
    const porcentajeNum = totalPerfilesDeclarados > 0 ? Math.round((totalActivos / totalPerfilesDeclarados) * 100) : 0;
    const valorPorcentajeOutput = `${totalActivos} de ${totalPerfilesDeclarados} activos (${porcentajeNum}%)`;

    // 4. MATRICES DE RIESGO E INCORPORACIÓN DE REGLAS DE NEGOCIO (Multi-Party Approval)
    let riesgo001 = "Bajo";
    let comentario001 = `Se han identificado técnicamente ${totalPerfilesDeclarados} perfiles de inicio de sesión único (SSO) declarados. Nota: La modificación de estos perfiles puede estar sujeta a políticas de aprobación multipartita.`;

    let riesgo002, comentario002;
    if (porcentajeNum === 0) {
      riesgo002 = "Alto";
      comentario002 = "Ningún perfil de autenticación SAML/OIDC mapeado en la organización está haciendo uso operativo de la configuración SSO. Si realizó asignaciones recientes, valide que no estén pendientes por aprobación multipartita.";
    } else if (porcentajeNum === 100) {
      riesgo002 = "Bajo";
      comentario002 = "El 100% de los perfiles de inicio de sesión único configurados en la organización tienen una redirección criptográfica activa mediante asignaciones.";
    } else {
      riesgo002 = "Medio";
      comentario002 = `Existe una implementación parcial del SSO de terceros. Únicamente el ${porcentajeNum}% de los perfiles configurados reciben aserciones de identidad vigentes.`;
    }

    Logger.log(`[RESULTADO ID-001] Perfiles: ${respuestaConcretaID001} | Riesgo: ${riesgo001}`);
    Logger.log(`[RESULTADO ID-002] Proporción Activa: ${valorPorcentajeOutput} | Riesgo: ${riesgo002}`);

    // 5. RETORNO PARA EL FACADE
    return {
      name: this.name,
      raw: { perfiles: json, asignaciones: asignacionesVivas },

      valorPrincipal: respuestaConcretaID001,
      comentario001: comentario001,
      riesgo001: riesgo001,
      score001: this.calcularScoreDeRiesgo(riesgo001),
      
      valorSecundario: valorPorcentajeOutput,
      comentario002: comentario002,
      riesgo002: riesgo002,
      score002: this.calcularScoreDeRiesgo(riesgo002)
    };
  }
}