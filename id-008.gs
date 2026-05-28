/**
 * Estrategia para auditar la adopción de la Verificación en dos pasos (2SV)
 * Utiliza la Admin SDK: Reports API
 * Se integra el motor de paginación para dominios extensos y manejo defensivo
 * ante la latencia de consolidación de Google (Típicamente de 3 a 4 días).
 */
class TwoStepVerificationCounter extends ApiStrategy {
  constructor() {
    // 1. Definimos el ID-008 y sus llaves de inyección
    const configIDs = [
      { 
        id: "ID-008", 
        valueKey: "valorPrincipal", 
        noteKey: "comentario008",
        riskKey: "riesgo008",
        scoreKey: "score008"
      }
    ];

    super("2-Step Verification Audit", configIDs);

    // 2. Calculamos la fecha más reciente (Hace 3 días)
    // Nota: A veces Google requiere hasta 4 días de latencia para consolidar el JSON.
    const fecha = new Date();
    fecha.setDate(fecha.getDate() - 3); 
    const dateString = Utilities.formatDate(fecha, Session.getScriptTimeZone(), "yyyy-MM-dd");

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

  calcularScoreDeRiesgo(nivelRiesgo) {
    if (!nivelRiesgo) return null;
    const riesgoNormalizado = nivelRiesgo.toString().trim().toLowerCase();
    
    if (riesgoNormalizado === "alto") return 1;
    if (riesgoNormalizado === "medio") return 2;
    if (riesgoNormalizado === "bajo") return 3;
    
    return null;
  }

  parseResponse(json) {
    // 1. EVALUACIÓN DE ERRORES DE RED O AUTENTICACIÓN
    if (json.error) {
      Logger.log(`[ERROR API] 2SV Counter Audit: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo008: "Medio",
        score008: 2,
        comentario008: `Error de lectura vía API Reports que impide auditar la adopción: ${json.error.message}`
      };
    }

    // 2. EXTRACCIÓN Y PAGINACIÓN OBLIGATORIA
    let reportes = json.usageReports || [];

    // Si la llamada inicial del Facade nos dejó páginas pendientes, re-hidratamos todo el bloque
    if (json.nextPageToken) {
      Logger.log("[INFO] Paginación detectada en Reports API. Extrayendo los lotes de usuarios restantes...");
      const todosLosReportes = this.fetchPaginated(this.url, "usageReports");
      if (todosLosReportes) reportes = todosLosReportes;
    }

    const totalUsuarios = reportes.length;

    // 3. MANEJO DEFENSIVO ANTE LATENCIA DE DATOS DE GOOGLE
    // Si el arreglo viene vacío, no es que no haya usuarios, es que Google no ha generado el reporte.
    if (totalUsuarios === 0) {
      Logger.log("[AVISO] La API de Reports retornó 0 reportes. Posible retraso en la consolidación del Data Center.");
      return {
        name: this.name,
        raw: json,
        valorPrincipal: "Sin datos consolidados",
        riesgo008: "Medio", // Riesgo neutral ya que es un fallo de infraestructura temporal
        score008: 2,
        comentario008: "AUDITORÍA INCONCLUSIVA: El reporte de uso de Google para la fecha calculada aún no se ha consolidado en el Data Center. Intente ejecutar el análisis nuevamente mañana."
      };
    }

    // 4. LÓGICA DE NEGOCIO Y CÁLCULO DE ADOPCIÓN
    let usuariosCon2SV = 0;

    reportes.forEach(reporte => {
      const parametros = reporte.parameters || [];
      // Buscamos estrictamente la métrica de enrolamiento 2SV en el reporte del usuario
      const param2SV = parametros.find(p => p.name === "accounts:is_2sv_enrolled");

      if (param2SV && param2SV.boolValue === true) {
        usuariosCon2SV++;
      }
    });

    const porcentajeNum = Math.round((usuariosCon2SV / totalUsuarios) * 100);
    // Mejoramos la legibilidad del output inyectando los números reales
    const valorPorcentajeOutput = `${usuariosCon2SV} de ${totalUsuarios} (${porcentajeNum}%)`;

    // 5. APLICACIÓN DE MATRICES DE RIESGO
    let riesgo008, comentario008;

    if (porcentajeNum === 0) {
      riesgo008 = "Alto";
      comentario008 = "Ningún usuario de la organización tiene activa la verificación en dos pasos (2SV). Las identidades dependen únicamente del esquema tradicional de contraseñas, constituyendo una vulnerabilidad crítica ante ataques de suplantación.";
    } else if (porcentajeNum === 100) {
      riesgo008 = "Bajo";
      comentario008 = "CUMPLIMIENTO: La totalidad (100%) de los usuarios reportados tiene la verificación en dos pasos (2SV) configurada y operando de manera activa.";
    } else {
      riesgo008 = "Medio";
      comentario008 = `Existe una adopción fragmentada del ${porcentajeNum}%. Una fracción de los usuarios interactúa con el entorno careciendo de un segundo factor de autenticación.`;
    }

    Logger.log(`[RESULTADO ID-008] Adopción 2SV: ${valorPorcentajeOutput} | Riesgo: ${riesgo008}`);

    // 6. RETORNAR EL OBJETO CONSOLIDADO PARA LA FACADE
    return {
      name: this.name,
      raw: { totalAnalizados: totalUsuarios, data: json },
      valorPrincipal: valorPorcentajeOutput,
      comentario008: comentario008,
      riesgo008: riesgo008,
      score008: this.calcularScoreDeRiesgo(riesgo008)
    };
  }
}