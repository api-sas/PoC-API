/**
 * Estrategia para auditar el aprovisionamiento de identidades externas (ej. JumpCloud, Okta, Azure)
 * Utiliza la Admin SDK: Directory API
 * Delega la búsqueda al motor de Google usando consultas estructuradas (query=externalId:*)
 * e implementa paginación masiva para evitar falsos negativos en dominios grandes.
 */
class ExternalProvisioningStrategy extends ApiStrategy {
  constructor() {
    // 1. Matriz de configuración para el ID-028
    const configIDs = [
      { 
        id: "ID-028", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario028",
        riskKey: "riesgo028",
        scoreKey: "score028"
      }
    ];

    super("External Identity Provisioning Audit", configIDs);

    // 2. MIGRACIÓN ARQUITECTÓNICA: Uso de consulta estructurada nativa
    // En lugar de descargar todo el directorio y filtrar en código, ordenamos 
    // a Google que solo nos devuelva las identidades vinculadas a un IdP.
    const query = "externalId:*";
    this.url = `https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&query=${encodeURIComponent(query)}`;
    
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
    // 1. EVALUACIÓN DEFENSIVA DE ERRORES DE API
    if (json.error) {
      Logger.log(`[ERROR API] Provisioning Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR_API",
        riesgo028: "Medio",
        score028: 2,
        comentario028: `Error de lectura en la API Directory: ${json.error.message}. Impide auditar el estado del aprovisionamiento de identidades automatizadas.`
      };
    }

    // 2. EXTRACCIÓN MASIVA (PAGINACIÓN OBLIGATORIA)
    // Como ya usamos `query=externalId:*`, todos los usuarios en este JSON ya están sincronizados
    let usuariosSincronizados = json.users || [];

    // Si la llamada inicial detecta más de 500 cuentas sincronizadas, hidratamos el resto
    if (json.nextPageToken) {
      Logger.log("[INFO] Directorio extenso detectado. Paginando para contar todas las identidades externas...");
      const todos = this.fetchPaginated(this.url, "users");
      if (todos) usuariosSincronizados = todos;
    }

    const totalSincronizados = usuariosSincronizados.length;

    // --- 3. LÓGICA DE NEGOCIO Y MATRICES DE RIESGO ---
    let respuestaConcreta;
    let riesgo028, comentario028;

    if (totalSincronizados > 0) {
      // Caso 1: Hay usuarios sincronizados automáticamente con un IdP
      respuestaConcreta = `Habilitado (${totalSincronizados} perfiles)`;
      riesgo028 = "Bajo";
      comentario028 = `CUMPLIMIENTO: Existen ${totalSincronizados} perfiles en el directorio que cuentan con metadatos de identificadores corporativos externos (externalId). Esto evidencia que el ciclo de vida de las identidades se orquesta y aprovisiona de forma transaccional mediante un Proveedor de Identidad (IdP) centralizado.`;
      
    } else {
      // Caso 2: No hay sincronización detectada
      respuestaConcreta = "Deshabilitado";
      riesgo028 = "Medio";
      comentario028 = "Ningún usuario en el directorio posee el metadato 'externalId' configurado. Esto indica que el aprovisionamiento de cuentas de la organización se gestiona de forma aislada o manual, sin vinculación ininterrumpida con un Proveedor de Identidad (IdP) o Directorio Activo.";
    }

    // Log técnico para trazabilidad forense
    Logger.log(`[RESULTADO ID-028] Aprovisionamiento Externo: ${respuestaConcreta} | Riesgo: ${riesgo028}`);

    // 4. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      // Retornamos un resumen para no saturar la memoria si hay miles de usuarios
      raw: { totalSincronizados: totalSincronizados, payloadOmited: true },
      valorPrincipal: respuestaConcreta,
      comentario028: comentario028,
      riesgo028: riesgo028,
      score028: this.calcularScoreDeRiesgo(riesgo028)
    };
  }
}