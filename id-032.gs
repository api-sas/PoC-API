/**
 * Estrategia para auditar alertas de seguridad (Phishing, Accesos Anómalos)
 * Utiliza la Google Workspace Alert Center API
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-032
 */
class SecurityAlertsAuditStrategy extends ApiStrategy {
  constructor() {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-032 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-032", 
        valueKey: "valorPrincipal", // Entregará el total de alertas (entero)
        noteKey: "comentario032",
        riskKey: "riesgo032",
        scoreKey: "score032"
      }
    ];

    super("Security Alerts & Threat Visibility", configIDs);
    
    // Consultamos las alertas del centro de seguridad
    this.url = "https://alertcenter.googleapis.com/v1beta1/alerts";
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
      Logger.log(`[ERROR CRÍTICO] Alert Center API falló: ${json.error.message || JSON.stringify(json.error)}`);
      
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: `ERROR API: ${json.error.message || "Revisa los logs"}`, 
        riesgo032: "Medio",
        score032: 2,
        comentario032: "Error de autenticación, lectura o permisos insuficientes (scopes) en la API Alert Center que impide conectarse al centro de seguridad para auditar la existencia de amenazas."
      };
    }

    const alertas = json.alerts || [];
    const totalAlertas = alertas.length;

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta = totalAlertas;
    let riesgo032, comentario032;

    if (totalAlertas > 0) {
      // Caso 1: Existen alertas registradas (visibilidad activa)
      riesgo032 = "Medio";
      comentario032 = "El centro de alertas documenta la existencia de incidentes de seguridad, evidenciando la detección de amenazas activas en la organización que pueden incluir ataques de phishing o accesos sospechosos.";

      // Filtros para detalle técnico en la consola (Logs)
      const phishing = alertas.filter(a => a.type && a.type.toLowerCase().includes('phishing')).length;
      const anomalos = alertas.filter(a => a.type && (a.type.toLowerCase().includes('login') || a.type.toLowerCase().includes('suspicious'))).length;
      
      Logger.log(`[LOG] Alert Audit: Detectadas ${phishing} alertas de Phishing y ${anomalos} de Accesos Anómalos. Total: ${totalAlertas} | Riesgo: ${riesgo032}`);
      
    } else {
      // Caso 2: El centro de alertas está vacío
      riesgo032 = "Bajo";
      comentario032 = "El centro de alertas no reporta incidentes de seguridad activos, indicando la ausencia de amenazas detectadas, como campañas de phishing o intentos de inicio de sesión anómalos.";
      
      Logger.log(`[LOG] Alert Audit: No se detectaron amenazas activas en el centro de alertas. | Riesgo: ${riesgo032}`);
    }

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario032: comentario032,
      riesgo032: riesgo032,
      score032: this.calcularScoreDeRiesgo(riesgo032)
    };
  }
}