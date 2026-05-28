/**
 * Estrategia para auditar a los Administradores de Dispositivos Móviles (MDM).
 * Utiliza la Admin SDK Directory API (Role Assignments)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-039
 */
class MobileAdminRoleStrategy extends ApiStrategy {
  constructor(customerId, roleId) { 
    // 1. Nueva arquitectura: Definimos la matriz con el ID-039 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-039", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario039",
        riskKey: "riesgo039",
        scoreKey: "score039"
      }
    ];

    super("Mobile Device Admin Role Audit", configIDs);
    
    // Si no encuentra el rol, asignamos un string seguro para evitar errores 400
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
      Logger.log(`[ERROR] Mobile Admin Assignments: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo039: "Medio",
        score039: 2,
        comentario039: "Error de lectura, conectividad o permisos insuficientes en la API Directory que impide extraer la lista de asignaciones de roles y auditar a los administradores de dispositivos móviles."
      };
    }

    const items = json.items || [];
    const adminCount = items.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo039, comentario039;

    if (adminCount > 0) {
      // Caso 1: Existen usuarios con el rol de Administrador MDM delegado
      respuestaConcreta = "Habilitado";
      riesgo039 = "Medio";
      comentario039 = "Existen cuentas de usuario en el directorio que tienen asignado activamente el rol de Administrador de dispositivos móviles, otorgándoles privilegios globales para gestionar las políticas, configuraciones y el parque de dispositivos MDM.";
    } else {
      // Caso 2: No hay asignaciones para este rol o el rol no tiene usuarios
      respuestaConcreta = "Deshabilitado";
      riesgo039 = "Bajo";
      comentario039 = "La consulta a la API no devolvió usuarios con el rol específico de Administrador de dispositivos móviles asignado; nadie ostenta este privilegio delegado actualmente en el dominio.";
    }

    // Trazabilidad técnica para la consola del auditor
    const adminIds = items.map(item => item.assignedTo);
    Logger.log(`[LOG] Mobile Admin Audit: Se detectaron ${adminCount} asignaciones. Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo039}`);
    if (adminCount > 0) {
      Logger.log(`[DETALLE] IDs de Administradores MDM: ${adminIds.join(", ")}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario039: comentario039,
      riesgo039: riesgo039,
      score039: this.calcularScoreDeRiesgo(riesgo039)
    };
  }
}