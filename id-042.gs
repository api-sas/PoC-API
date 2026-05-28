/**
 * Estrategia para auditar si el servicio de Google Vault está habilitado.
 * Utiliza la Cloud Identity API (v1beta1)
 * Contiene la lógica de negocio (hardcodeada) basada en toadd.csv para ID-042
 */
class VaultServiceStatusStrategy extends ApiStrategy {
  constructor(customerId) {
    // 1. Nueva arquitectura: Definimos la matriz con el ID-042 y todas sus llaves
    const configIDs = [
      { 
        id: "ID-042", 
        valueKey: "valorPrincipal", // "Habilitado" o "Deshabilitado"
        noteKey: "comentario042",
        riskKey: "riesgo042",
        scoreKey: "score042"
      }
    ];

    super("Google Vault Service Status Audit", configIDs);
    
    // Filtro con el operador && apuntando a la configuración de Vault
    const filter = `customer=="customers/${customerId}" && setting.type=="vault.service_status"`;
    this.url = `https://cloudidentity.googleapis.com/v1beta1/policies?filter=${encodeURIComponent(filter)}`;
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
      Logger.log(`[ERROR] Vault Service Policy: ${json.error.message || JSON.stringify(json.error)}`);
      return { 
        name: this.name, 
        raw: json,
        valorPrincipal: "ERROR",
        riesgo042: "Medio",
        score042: 2,
        comentario042: "Error de lectura, conectividad o permisos insuficientes en la API Cloud Identity que impide extraer y auditar el estado actual del servicio de Google Vault."
      };
    }

    const policies = json.policies || [];

    // Filtramos para encontrar políticas que habiliten explícitamente el servicio
    const enabledPolicies = policies.filter(policy => {
      if (policy.setting) {
        // Extraemos el nodo de configuración
        const configNode = policy.setting.vaultServiceStatus || policy.setting.serviceStatus || policy.setting.value || policy.setting;
        
        // Convertimos a string y mayúsculas para hacer una búsqueda tolerante a cambios en la beta.
        const nodeStr = JSON.stringify(configNode).toUpperCase();
        
        return nodeStr.includes('"STATE":"ENABLED"') || 
               nodeStr.includes('"SERVICESTATE":"ENABLED"') || 
               nodeStr.includes('"ENABLED":TRUE') ||
               (configNode.state && configNode.state === 'ENABLED');
      }
      return false;
    });

    // --- 2. LÓGICA DE SALIDA Y APLICACIÓN DE REGLAS DE NEGOCIO ---
    let respuestaConcreta;
    let riesgo042, comentario042;

    if (enabledPolicies.length > 0) {
      // Caso 1: La política confirma que Google Vault está habilitado
      respuestaConcreta = "Habilitado";
      riesgo042 = "Medio";
      comentario042 = "La política de estado del servicio en Cloud Identity confirma que Google Vault se encuentra habilitado activamente para la organización.";
    } else {
      // Caso 2: El JSON viene vacío o la política existe pero indica que está apagado ("DISABLED")
      respuestaConcreta = "Deshabilitado";
      riesgo042 = "Bajo";
      comentario042 = "La consulta a la API indica que el servicio de Google Vault se encuentra inactivo o no cuenta con una política de habilitación configurada.";
    }

    // Trazabilidad técnica para la consola del auditor
    Logger.log(`[LOG] Vault Status Audit: Resultado -> ${respuestaConcreta} | Riesgo: ${riesgo042}`);

    // 3. RETORNAR EL OBJETO CONSOLIDADO PARA LA CLASE BASE
    return {
      name: this.name,
      raw: json,
      valorPrincipal: respuestaConcreta,
      comentario042: comentario042,
      riesgo042: riesgo042,
      score042: this.calcularScoreDeRiesgo(riesgo042)
    };
  }
}