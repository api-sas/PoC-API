/**
 * Estrategia para auditar si se permite la reutilización de contraseñas.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para el ID-004
 */
class PasswordReusePolicyStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-004 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-004", 
        valueKey: "valorPrincipal",
        noteKey: "comentario004",
        riskKey: "riesgo004",
        scoreKey: "score004"
      }
    ];

    super("Password Reuse Policy Audit", configIDs);
    
    // Filtro para la política de contraseñas
    const filter = `customer=="customers/${customerId}" && setting.type=="security.password"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
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
      Logger.log(`[ERROR] Password Reuse Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo004: "Medio",
        score004: 2,
        comentario004: "Error de lectura vía API Cloud Identity que impide validar el estado técnico de la política de reutilización de contraseñas."
      };
    }

    const policies = json.policies || [];

    // Filtramos para encontrar políticas que permitan explícitamente la reutilización (allowReuse: true)
    const reuseEnabledPolicies = policies.filter(policy => {
      if (policy.setting && policy.setting.password) {
        return policy.setting.password.allowReuse === true;
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo004, comentario004;

    if (reuseEnabledPolicies.length > 0) {
      // Caso 1: La política permite explícitamente reutilizar contraseñas (Habilitado)
      respuestaConcreta = "Habilitado";
      riesgo004 = "Medio";
      comentario004 = "La política de contraseñas configurada en el dominio permite explícitamente a los usuarios la reutilización de contraseñas anteriores.";
    
    } else if (policies.length === 0) {
      // Caso 2: El JSON viene vacío, no hay política de contraseñas configurada (Deshabilitado)
      respuestaConcreta = "Deshabilitado";
      riesgo004 = "Alto";
      comentario004 = "La organización no tiene configurada ninguna directiva de contraseñas locales en la consola de Google Workspace.";
    
    } else {
      // Caso 3: La política existe pero bloquea la reutilización (allowReuse: false)
      respuestaConcreta = JSON.stringify(json);
      riesgo004 = "Bajo";
      comentario004 = "La política de contraseñas está activa e impide explícitamente el reciclaje de credenciales previamente utilizadas.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Password Reuse Audit: Resultado final -> ${respuestaConcreta} | Riesgo: ${riesgo004}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario004: comentario004,
      riesgo004: riesgo004,
      score004: this.calcularScoreDeRiesgo(riesgo004)
    };
  }
}