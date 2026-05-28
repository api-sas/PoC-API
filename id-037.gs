/**
 * Estrategia para auditar a los Administradores de Soporte Técnico (Help Desk).
 * Evalúa si el permiso de reseteo de contraseñas es global o restringido por OU.
 * Utiliza la Admin SDK Directory API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-037
 */
class HelpDeskAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-037 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-037", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario037",
        riskKey: "riesgo037",
        scoreKey: "score037"
      }
    ];

    super("Help Desk Admin Role Audit", configIDs);
    
    // Si no encuentra el rol, usamos un string seguro para no romper la URL
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
      Logger.log(`[ERROR] Help Desk Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo037: "Medio",
        score037: 2,
        comentario037: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y auditar a los administradores de soporte técnico."
      };
    }

    const items = json.items || [];
    let globalCount = 0;
    let scopedCount = 0;

    // Iteramos sobre las asignaciones para evaluar el nivel de privilegio (Global vs OU)
    for (const item of items) {
      // Verificamos si tiene un ámbito restringido (orgUnitId)
      if (item.orgUnitId && item.orgUnitId !== "/") {
        scopedCount++;
      } else {
        globalCount++;
      }
    }

    const adminCount = globalCount + scopedCount;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo037, comentario037;

    if (adminCount > 0) {
      // Caso 1: Existen usuarios con el rol de Soporte Técnico
      respuestaConcreta = "Habilitado";
      riesgo037 = "Medio";
      comentario037 = "Existen cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de soporte técnico, otorgándoles permisos delegados para ver perfiles de usuarios y restablecer contraseñas.";
    } else {
      // Caso 2: No hay asignaciones para este rol
      respuestaConcreta = "Deshabilitado";
      riesgo037 = "Bajo";
      comentario037 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de soporte técnico asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Help Desk Admin Audit: ${adminCount} asignaciones detectadas (${globalCount} globales, ${scopedCount} restringidos por OU). Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo037}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario037: comentario037,
      riesgo037: riesgo037,
      score037: this.calcularScoreDeRiesgo(riesgo037)
    };
  }
}