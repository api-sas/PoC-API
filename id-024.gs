/**
 * Estrategia para auditar si los Superadministradores y VIPs 
 * están protegidos por el Programa de Protección Avanzada (Titanium).
 * Cruza datos paginados masivos de Reports API y Directory API.
 */
class SuperAdminSecurityStrategy extends ApiStrategy {
  constructor() {
    // 1. Matriz de configuración para el ID-024
    const configIDs = [
      { 
        id: "ID-024", 
        valueKey: "valorPrincipal", // Entregará el porcentaje (Ej: "80%")
        noteKey: "comentario024",
        riskKey: "riesgo024",
        scoreKey: "score024"
      }
    ];

    super("SuperAdmin APP Protection Audit", configIDs);
    
    // URL base: Eventos de enrolamiento Titanium (Reports API)
    this.urlTitanium = "https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/login?eventName=titanium_enroll";
    
    // URL secundaria: Lista de administradores del dominio (Directory API)
    this.urlAdmins = "https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&query=isAdmin=true";
    
    this.category = "Identidad y autenticación";
  }

  // La Facade ejecutará la primera llamada contra la Reports API
  getRequestConfig() {
    return {
      url: this.urlTitanium,
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

  parseResponse(titaniumJson) {
    // 1. EVALUACIÓN DEFENSIVA DE LA PRIMERA API (Reports - Titanium)
    if (titaniumJson.error) {
      Logger.log(`[ERROR API] SuperAdmin Security Audit (Titanium): ${titaniumJson.error.message || JSON.stringify(titaniumJson.error)}`);
      return { 
        name: this.name, 
        raw: titaniumJson,
        valorPrincipal: "ERROR_API",
        riesgo024: "Medio",
        score024: 2,
        comentario024: `Error al leer logs de Titanium: ${titaniumJson.error.message}. Impide auditar el estado de los administradores.`
      };
    }

    // 2. EXTRACCIÓN MASIVA DE EVENTOS TITANIUM (PAGINACIÓN)
    let eventos = titaniumJson.items || [];
    
    // Si hay más de una página de logs, re-hidratamos todo el historial usando la clase padre
    if (titaniumJson.nextPageToken) {
      Logger.log("[INFO] Paginación detectada en logs de Titanium. Extrayendo historial completo...");
      const todosLosEventos = this.fetchPaginated(this.urlTitanium, "items");
      if (todosLosEventos) eventos = todosLosEventos;
    }

    // Set para obtener usuarios únicos (inmune a enrolamientos múltiples históricos)
    const usuariosTitanium = new Set();
    eventos.forEach(ev => {
      if (ev.actor && ev.actor.email) {
        usuariosTitanium.add(ev.actor.email.toLowerCase());
      }
    });

    // 3. EXTRACCIÓN MASIVA DE ADMINISTRADORES (Directory API)
    Logger.log("[INFO] Consultando Directorio para listar administradores...");
    // Usamos el paginador universal para traer a TODOS los admins automáticamente
    const administradores = this.fetchPaginated(this.urlAdmins, "users");

    // Manejo en caso de que falle la petición de la Directory API
    if (!administradores) {
      return { 
        name: this.name, 
        raw: { titanium: eventos, directoryError: true },
        valorPrincipal: "ERROR_API",
        riesgo024: "Medio",
        score024: 2,
        comentario024: "Error de lectura o permisos en la Directory API. Imposible listar a los administradores para cruzar los datos."
      };
    }

    const totalAdmins = administradores.length;

    // --- 4. LÓGICA DE NEGOCIO Y MATRICES DE RIESGO ---
    let respuestaConcreta;
    let riesgo024, comentario024;

    if (totalAdmins > 0) {
      // Cruzar datos: Averiguar cuántos admins carecen de protección
      const adminsSinProteccion = administradores.filter(admin => 
        !usuariosTitanium.has(admin.primaryEmail.toLowerCase())
      );

      const adminsProtegidos = totalAdmins - adminsSinProteccion.length;
      const porcentajeNum = Math.round((adminsProtegidos / totalAdmins) * 100);
      
      // Formato mejorado para inyectar en la hoja de cálculo
      respuestaConcreta = `${adminsProtegidos} de ${totalAdmins} protegidos (${porcentajeNum}%)`;

      // Reglas de negocio del CSV
      if (porcentajeNum === 0) {
        riesgo024 = "Alto";
        comentario024 = "Ningún usuario con privilegios de administrador en el dominio se encuentra inscrito en el Programa de Protección Avanzada. Esto representa una vulnerabilidad crítica ante ataques de phishing dirigidos.";
      } else if (porcentajeNum === 100) {
        riesgo024 = "Bajo";
        comentario024 = "CUMPLIMIENTO: La totalidad (100%) de las cuentas con privilegios de administrador han completado su inscripción en el Programa de Protección Avanzada.";
      } else {
        // Para administradores, cualquier adopción que no sea del 100% es un riesgo ALTO
        riesgo024 = "Alto";
        comentario024 = `Existe una brecha en la protección de cuentas privilegiadas; el ${100 - porcentajeNum}% de los administradores opera sin el blindaje del Programa de Protección Avanzada.`;
      }

      // Trazabilidad forense para el auditor
      if (adminsSinProteccion.length > 0) {
        Logger.log(`[ALERTA FORENSE] SuperAdmins expuestos (Sin APP): ${adminsSinProteccion.map(a => a.primaryEmail).join(", ")}`);
      }

    } else {
      // Caso anómalo: Dominio sin administradores listables
      respuestaConcreta = "Sin administradores";
      riesgo024 = "Medio";
      comentario024 = "La consulta al directorio no identificó cuentas con rol de administrador activo, impidiendo el cruce de datos y el cálculo del porcentaje de protección.";
    }

    Logger.log(`[RESULTADO ID-024] Protección APP en Admins: ${respuestaConcreta} | Riesgo: ${riesgo024}`);

    // 5. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: { totalTitaniumLogs: eventos.length, totalAdmins: totalAdmins },
      valorPrincipal: respuestaConcreta,
      comentario024: comentario024,
      riesgo024: riesgo024,
      score024: this.calcularScoreDeRiesgo(riesgo024)
    };
  }
}