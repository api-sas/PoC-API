/**
 * Estrategia para extraer los Super Administradores y evaluar privilegios máximos.
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-034
 */
class SuperAdminRoleAssignmentStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-034 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-034", 
        valueKey: "valorPrincipal", // Entregará el número entero de superadministradores
        noteKey: "comentario034",
        riskKey: "riesgo034",
        scoreKey: "score034"
      }
    ];

    super("Super Admin Role Assignments Audit", configIDs);
    
    // Asignamos un valor seguro en caso de que el rol no se encuentre para evitar romper la URL
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
      Logger.log(`[ERROR] Super Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo034: "Medio",
        score034: 2,
        comentario034: "Error de lectura o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y contabilizar a los superadministradores."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // Trazabilidad técnica para la consola del auditor
    const adminIds = items.map(item => item.assignedTo);
    
    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo034, comentario034;

    if (adminCount === 0) {
      // Caso 1: No se encontraron superadministradores
      riesgo034 = "Medio";
      comentario034 = "La consulta a la API no devolvió usuarios con el rol de superadministrador asignado, lo cual representa un estado inusual o anómalo en la administración del tenant de Google Workspace.";
    } else {
      // Caso 2: Se encontraron superadministradores
      riesgo034 = "Medio";
      comentario034 = "Indica la cantidad exacta de cuentas de usuario en el directorio que tienen asignado el rol de privilegios máximos globales (Superadministrador).";
      Logger.log(`[DETALLE] IDs de Super Administradores: ${adminIds.join(", ")}`);
    }

    Logger.log(`[LOG] Super Admin Audit: Se detectaron ${adminCount} super administradores. | Riesgo: ${riesgo034}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: adminCount,
      comentario034: comentario034,
      riesgo034: riesgo034,
      score034: this.calcularScoreDeRiesgo(riesgo034)
    };
  }
}