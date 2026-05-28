/**
 * Estrategia para auditar a los Administradores de Servicios.
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-038
 */
class ServicesAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-038 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-038", 
        valueKey: "valorPrincipal", // Entregará el número entero de administradores de servicios
        noteKey: "comentario038",
        riskKey: "riesgo038",
        scoreKey: "score038"
      }
    ];

    super("Services Admin Role Audit", configIDs);
    
    // Asignamos un valor seguro en caso de que el rol no se encuentre
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
      Logger.log(`[ERROR] Services Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo038: "Medio",
        score038: 2,
        comentario038: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y contabilizar a los administradores de servicios."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let riesgo038, comentario038;

    if (adminCount === 0) {
      // Caso 1: No hay administradores de servicios
      riesgo038 = "Bajo";
      comentario038 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de servicios asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    } else {
      // Caso 2: Existen administradores de servicios
      riesgo038 = "Medio";
      comentario038 = "Indica la cantidad exacta de cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de servicios, otorgándoles privilegios globales para gestionar la configuración y los permisos de los servicios de Google Workspace.";
    }

    // Trazabilidad técnica para la consola del auditor
    const adminIds = items.map(item => item.assignedTo);
    Logger.log(`[LOG] Services Admin Audit: Se detectaron ${adminCount} administradores de servicios. | Riesgo: ${riesgo038}`);
    if (adminCount > 0) {
      Logger.log(`[DETALLE] IDs de Administradores de Servicios: ${adminIds.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: adminCount,
      comentario038: comentario038,
      riesgo038: riesgo038,
      score038: this.calcularScoreDeRiesgo(riesgo038)
    };
  }
}