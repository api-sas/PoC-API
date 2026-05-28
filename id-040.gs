/**
 * Estrategia para auditar a los Administradores de Google Voice.
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-040
 */
class GoogleVoiceAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-040 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-040", 
        valueKey: "valorPrincipal", // Entregará el número entero de administradores de Google Voice
        noteKey: "comentario040",
        riskKey: "riesgo040",
        scoreKey: "score040"
      }
    ];

    super("Google Voice Admin Role Audit", configIDs);
    
    // Si no encuentra el rol (porque no usan Voice), evitamos error de URL
    const safeRoleId = roleId || "INVALID_ROLE"; 
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
      Logger.log(`[ERROR] Voice Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo040: "Medio",
        score040: 2,
        comentario040: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y contabilizar a los administradores de Google Voice."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo040, comentario040;

    if (adminCount === 0) {
      // Caso 1: No hay administradores de Google Voice
      riesgo040 = "Bajo";
      comentario040 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de Google Voice asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    } else {
      // Caso 2: Existen administradores de Google Voice
      riesgo040 = "Medio";
      comentario040 = "Indica la cantidad exacta de cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de Google Voice, otorgándoles privilegios globales para gestionar la configuración y el aprovisionamiento de este servicio.";
    }

    // Trazabilidad técnica para la consola del auditor
    const adminIds = items.map(item => item.assignedTo);
    Logger.log(`[LOG] Voice Admin Audit: Se detectaron ${adminCount} administradores de Google Voice. | Riesgo: ${riesgo040}`);
    
    if (adminCount > 0) {
      Logger.log(`[DETALLE] IDs de Administradores de Google Voice: ${adminIds.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: adminCount,
      comentario040: comentario040,
      riesgo040: riesgo040,
      score040: this.calcularScoreDeRiesgo(riesgo040)
    };
  }
}