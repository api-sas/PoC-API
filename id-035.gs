/**
 * Estrategia para auditar a los usuarios con el rol global de Administrador de Grupos.
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-035
 */
class GroupsAdminRoleAssignmentStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-035 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-035", 
        valueKey: "valorPrincipal",
        noteKey: "comentario035",
        riskKey: "riesgo035",
        scoreKey: "score035"
      }
    ];

    super("Groups Admin Role Assignments Audit", configIDs);
    
    // Usamos el roleId inyectado dinámicamente
    this.url = `https://admin.googleapis.com/admin/directory/v1/customer/${customerId}/roleassignments?roleId=${roleId}`;
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
      Logger.log(`[ERROR] Groups Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo035: "Medio",
        score035: 2,
        comentario035: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y auditar a los administradores de grupos."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo035, comentario035;

    if (adminCount > 0) {
      // Caso 1: Existen usuarios con el rol de Administrador de Grupos
      respuestaConcreta = "Habilitado";
      riesgo035 = "Medio";
      comentario035 = "Existen cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de Grupos, otorgándoles privilegios para gestionar la configuración y membresía de los grupos de Google.";
    } else {
      // Caso 2: No hay asignaciones para este rol (JSON vacío o items vacío)
      respuestaConcreta = "Deshabilitado";
      riesgo035 = "Bajo";
      comentario035 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de Grupos asignado; nadie ostenta este privilegio delegado actualmente.";
    }

    // Trazabilidad técnica para la consola
    const adminIds = items.map(item => item.assignedTo);
    Logger.log(`[LOG] Groups Admin Audit: Se detectaron ${adminCount} asignaciones. Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo035}`);
    if (adminCount > 0) {
      Logger.log(`[DETALLE] IDs de Administradores: ${adminIds.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario035: comentario035,
      riesgo035: riesgo035,
      score035: this.calcularScoreDeRiesgo(riesgo035)
    };
  }
}