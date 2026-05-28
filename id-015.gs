/**
 * Estrategia para auditar el inventario de Hardware FIDO2 (Security Keys y Passkeys)
 * Utiliza la Admin SDK: Reports API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-015
 */
class PasswordManagerStrategy extends ApiStrategy {
  constructor() {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-015 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-015", 
        valueKey: "valorPrincipal",
        noteKey: "comentario015",
        riskKey: "riesgo015",
        scoreKey: "score015"
      }
    ];

    super("FIDO2 Hardware Inventory", configIDs);

    const fecha = new Date();
    fecha.setDate(fecha.getDate() - 3);
    const dateString = Utilities.formatDate(fecha, "UTC", "yyyy-MM-dd");

    this.url = `https://admin.googleapis.com/admin/reports/v1/usage/users/all/dates/${dateString}`;
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
    // 1. EVALUACIÓN EN CASO DE ERROR DE API
    if (json.error) {
      Logger.log(`[ERROR] FIDO2 Hardware Inventory: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo015: "Medio",
        score015: 2,
        comentario015: "Error de lectura vía API Reports que impide extraer el inventario y calcular el porcentaje de adopción de hardware FIDO2."
      };
    }

    const reportes = json.usageReports || [];
    const totalUsuarios = reportes.length;
    let usuariosProtegidos = 0;

    // Filtramos y contamos los usuarios que tienen llaves de seguridad o passkeys
    reportes.forEach(reporte => {
      const parametros = reporte.parameters || [];
      
      const paramKeys = parametros.find(p => p.name === "accounts:num_security_keys");
      const paramPasskeys = parametros.find(p => p.name === "accounts:num_passkeys_enrolled");

      const nKeys = paramKeys ? (parseInt(paramKeys.intValue) || 0) : 0;
      const nPass = paramPasskeys ? (parseInt(paramPasskeys.intValue) || 0) : 0;

      // Si el usuario tiene AL MENOS una llave o passkey, se considera protegido por hardware
      if (nKeys > 0 || nPass > 0) {
        usuariosProtegidos++;
      }
    });

    // --- 2. LÓGICA DE SALIDA ESTANDARIZADA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo015, comentario015;

    if (totalUsuarios > 0) {
      // Calculamos el porcentaje redondeado a la parte entera
      const porcentajeNum = Math.round((usuariosProtegidos / totalUsuarios) * 100);
      respuestaConcreta = porcentajeNum + "%";

      if (porcentajeNum === 0) {
        // Caso 1: 0% - Nadie usa FIDO2
        riesgo015 = "Medio";
        comentario015 = "Ningún usuario registrado en los reportes de actividad cuenta con llaves de seguridad físicas o passkeys (FIDO2) enroladas en su cuenta.";
      } else if (porcentajeNum === 100) {
        // Caso 2: 100% - Totalidad usa FIDO2
        riesgo015 = "Bajo";
        comentario015 = "La totalidad de los usuarios reportados en el dominio tiene enrolada al menos una llave de seguridad física o passkey (FIDO2).";
      } else {
        // Caso 3: 1-99% - Adopción parcial
        riesgo015 = "Medio";
        comentario015 = "Existe una adopción parcial en la organización; solo una fracción de los usuarios utiliza llaves de seguridad físicas o passkeys (FIDO2).";
      }

    } else {
      // Caso 4: El JSON viene vacío o no hay usuarios registrados en el reporte
      respuestaConcreta = "Deshabilitado";
      riesgo015 = "Medio";
      comentario015 = "El reporte de uso de la API se encuentra vacío, indicando la ausencia de datos históricos recientes o de usuarios registrados para calcular la métrica.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] FIDO2 Inventory: ${usuariosProtegidos} de ${totalUsuarios} usuarios usan FIDO2. Resultado: ${respuestaConcreta} | Riesgo: ${riesgo015}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario015: comentario015,
      riesgo015: riesgo015,
      score015: this.calcularScoreDeRiesgo(riesgo015)
    };
  }
}