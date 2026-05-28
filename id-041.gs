/**
 * Estrategia para auditar a los Administradores de Android/Mobile.
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-041
 */
class AndroidAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-041 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-041", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario041",
        riskKey: "riesgo041",
        scoreKey: "score041"
      }
    ];

    super("Android Admin Role Audit", configIDs);
    
    // Si no encuentra el rol (ej. no ha sido creado en el tenant), usamos un string seguro para no romper la URL
    const safeRoleId = roleId || "INVALID"; 
    this.url = `https://admin.googleapis.com/admin/directory/v1/customer/${customerId}/roleassignments?roleId=${safeRoleId}`;
    this.category = "Administración";
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
      Logger.log(`[ERROR] Android Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      // Si el rol "INVALID" genera un error 400/404, se reportará aquí para no romper el código
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo041: "Medio",
        score041: 2,
        comentario041: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y auditar a los administradores de Android."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo041, comentario041;

    if (adminCount > 0) {
      // Caso 1: Existen usuarios con el rol de Administrador de Android delegado
      respuestaConcreta = "Habilitado";
      riesgo041 = "Medio";
      comentario041 = "Existen cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de Android, otorgándoles privilegios delegados para la gestión y configuración del servicio de Android en el sistema.";
    } else {
      // Caso 2: No hay asignaciones para este rol o la lista viene vacía
      respuestaConcreta = "Deshabilitado";
      riesgo041 = "Bajo";
      comentario041 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de Android asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    }

    // Trazabilidad técnica para la consola del auditor
    const adminIds = items.map(item => item.assignedTo);
    Logger.log(`[LOG] Android Admin Audit: Se detectaron ${adminCount} asignaciones. Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo041}`);
    if (adminCount > 0) {
      Logger.log(`[DETALLE] IDs de Administradores Android: ${adminIds.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario041: comentario041,
      riesgo041: riesgo041,
      score041: this.calcularScoreDeRiesgo(riesgo041)
    };
  }
}