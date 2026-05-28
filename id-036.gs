/**
 * Estrategia para auditar a los Administradores de Gestión de Usuarios.
 * Valida si sus poderes son globales o están restringidos por Unidad Organizativa (OU).
 * Utiliza la Admin SDK Directory API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-036
 */
class UserManagementAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-036 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-036", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario036",
        riskKey: "riesgo036",
        scoreKey: "score036"
      }
    ];

    super("User Management Admin Role Audit", configIDs);
    
    // Recibe el roleId inyectado dinámicamente
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
      Logger.log(`[ERROR] User Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo036: "Medio",
        score036: 2,
        comentario036: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y auditar a los administradores de gestión de usuarios."
      };
    }

    const items = json.items || [];
    let globalAdminCount = 0;
    let scopedAdminCount = 0;

    // Evaluamos el JSON y la propiedad orgUnitId para la auditoría técnica interna
    if (items.length > 0) {
      for (const item of items) {
        // En la API, si orgUnitId es "/" o no existe en algunos contextos, es Global.
        // Si tiene un ID específico, está limitado por OU.
        if (item.orgUnitId && item.orgUnitId !== "/") {
          scopedAdminCount++;
        } else {
          globalAdminCount++;
        }
      }
    }

    const totalCount = globalAdminCount + scopedAdminCount;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo036, comentario036;

    if (totalCount > 0) {
      // Caso 1: Existen usuarios con el rol de Gestión de Usuarios delegado
      respuestaConcreta = "Habilitado";
      riesgo036 = "Medio";
      comentario036 = "Existen cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de gestión de usuarios, otorgándoles permisos delegados para crear, eliminar y gestionar la seguridad de las cuentas.";
    } else {
      // Caso 2: No hay asignaciones para este rol
      respuestaConcreta = "Deshabilitado";
      riesgo036 = "Bajo";
      comentario036 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de gestión de usuarios asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] User Admin Audit: ${totalCount} asignaciones detectadas (${globalAdminCount} globales, ${scopedAdminCount} restringidos por OU). Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo036}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario036: comentario036,
      riesgo036: riesgo036,
      score036: this.calcularScoreDeRiesgo(riesgo036)
    };
  }
}