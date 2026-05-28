/**
 * Diccionario centralizado de valores por defecto de fábrica de Google Workspace.
 * Se utiliza para hidratar el JSON de políticas cuando Google omite configuraciones
 * porque están en su estado predeterminado.
 */
class DefaultPolicyValuesRegistry {
  /**
   * Retorna el objeto base de configuración para un tipo de política específico.
   * @param {string} settingType - El tipo de configuración
   * @return {Object|null} El valor por defecto o nulo si no está registrado.
   */
  static getDefaults(settingType) {
    const registry = {
      "security.password": {
        allowedStrength: "WEAK", // Si Google no lo envía, la fuerza base es débil
        enforceRequirementsAtLogin: false,
        allowReuse: true,
        enforceStrongPassword: false
      },
      "security.lessSecureApps": {
        allowLessSecureApps: false // Por defecto, el acceso LSA suele estar bloqueado
      },
      // Puedes ir agregando más tipos de políticas a medida que crees nuevas estrategias
      "chat.chat_history": {
        history_on_by_default: false
      }
    };

    return registry[settingType] || null;
  }
}

/**
 * Extractor maestro de políticas. Descarga todo el árbol de políticas 
 * de Cloud Identity y lo mantiene en la memoria RAM del script.
 */
class GlobalPolicyExtractor {
  constructor(authService, customerId) {
    this.auth = authService;
    this.customerId = customerId;
    this.rawPolicies = []; // Aquí vivirá el árbol en memoria
  }

  /**
   * Ejecuta la descarga completa de políticas respetando estrictamente el límite de 1 QPS.
   * @returns {Array} Matriz con todas las políticas de la organización.
   */
  fetchTree() {
    Logger.log("[POLICY EXTRACTOR] Iniciando extracción global de políticas...");
    let pageToken = "";
    const baseUrl = `https://cloudidentity.googleapis.com/v1/policies?customer=customers/${this.customerId}`;
    
    do {
      let url = baseUrl;
      if (pageToken) {
        url += `&pageToken=${pageToken}`;
      }
      
      const config = {
        method: "get",
        headers: this.auth.getAuthHeader(),
        muteHttpExceptions: true
      };

      const response = UrlFetchApp.fetch(url, config);
      const json = JSON.parse(response.getContentText());

      if (json.error) {
        Logger.log(`[CRÍTICO] Error extrayendo políticas: ${json.error.message}`);
        break; // Rompemos el ciclo si hay un error fatal
      }

      if (json.policies && json.policies.length > 0) {
        // Enriquecemos (hidratamos) las políticas sobre la marcha con sus valores por defecto
        const hydratedPolicies = json.policies.map(policy => this._hydratePolicy(policy));
        this.rawPolicies = this.rawPolicies.concat(hydratedPolicies);
      }

      pageToken = json.nextPageToken;
      
      if (pageToken) {
        Logger.log("[POLICY EXTRACTOR] Paginación detectada. Aplicando retardo obligatorio de 1000ms para evitar Error 429 (Límite QPS)...");
        Utilities.sleep(1000); 
      }

    } while (pageToken);

    Logger.log(`[POLICY EXTRACTOR] Extracción completada. ${this.rawPolicies.length} políticas cacheadas en memoria.`);
    return this.rawPolicies;
  }

  /**
   * Retorna el árbol de políticas ya descargado.
   */
  getPolicies() {
    return this.rawPolicies;
  }

  /**
   * Función privada que fusiona el JSON recibido de Google con los valores base del registro.
   */
  _hydratePolicy(policy) {
    if (!policy || !policy.setting || !policy.setting.type) return policy;

    const settingType = policy.setting.type;
    const defaultValues = DefaultPolicyValuesRegistry.getDefaults(settingType);

    if (defaultValues) {
      // Usamos el nombre del nodo principal (ej. "password" de "security.password")
      const nodeName = settingType.split('.').pop(); 
      
      if (policy.setting[nodeName]) {
        // Fusionamos los valores por defecto con los que sí trajo la API (los de la API mandan)
        policy.setting[nodeName] = { ...defaultValues, ...policy.setting[nodeName] };
      } else {
        // Si el nodo no existe en absoluto, lo inyectamos completo
        policy.setting[nodeName] = defaultValues;
      }
    }
    return policy;
  }
}