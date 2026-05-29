/**
 * Diccionario centralizado de valores por defecto de fábrica de Google Workspace.
 * Se utiliza para hidratar el JSON de políticas cuando Google omite configuraciones
 * porque están en su estado predeterminado.
 */
class DefaultPolicyValuesRegistry {
  /**
   * Retorna las politicas que son mencionadas a continuación
   * @param {string} settingType - El tipo de configuración
   * @return {Object|null} El valor por defecto o nulo si no está registrado.
   */
  static getDefaults(settingType) {
    const registry = {
      "security.password": {
        allowedStrength: "WEAK", // Si Google no lo envía, valor por defecto
        enforceRequirementsAtLogin: false,
        allowReuse: true,
        enforceStrongPassword: false
      },
      "security.lessSecureApps": {
        allowLessSecureApps: false // Por defecto, el acceso LSA suele estar bloqueado
      },
    };
    return registry[settingType] || null;
  }
}

/**
 * Extrae las políticas de los usuarios de la OU raíz [fetchTree]
 * y lo mantiene en la memoria RAM del script.
 */
class GlobalPolicyExtractor {
  constructor(authService, customerId) {
    this.auth = authService;
    this.customerId = customerId;
    this.rawPolicies = []; // json gigante con todas las configuraciones solicitadas
  }

  /**
   * Ejecuta Policy Query para traer todas las politicas.
   * @returns {Array} Matriz con todas las políticas de la organización.
   */
  fetchTree() {
    Logger.log("[POLICY QUERY] Iniciando extracción global de políticas...");
    let pageToken = "";
    const baseUrl = `https://cloudidentity.googleapis.com/v1/policies?customer=customers/${this.customerId}`;
    
    do {
      let url = baseUrl;
      if (pageToken) {
        url += `&pageToken=${pageToken}`;
      }
      
      const authHeader = this.auth.getAuthHeader();
      const config = {
        method: "get",
        headers: {
          ...authHeader,
          "Cache-Control": "no-cache, no-store, max-age=0, must-revalidate",
          "Pragma": "no-cache"
        },
        muteHttpExceptions: true
      };

      const response = UrlFetchApp.fetch(url, config);
      const json = JSON.parse(response.getContentText());

      if (json.error) {
        Logger.log(`[CRÍTICO] Error extrayendo políticas: ${json.error.message}`);
        break; // Rompemos el ciclo si hay un error fatal
      }

      if (json.policies && json.policies.length > 0) {
        // si las politicas vienen vacías, se aplican los valores por defecto de las políticas
        const hydratedPolicies = json.policies.map(policy => this._hydratePolicy(policy));
        this.rawPolicies = this.rawPolicies.concat(hydratedPolicies);
      }

      pageToken = json.nextPageToken;
      
      if (pageToken) {
        Logger.log("[POLICY QUERY] Paginación detectada. Aplicando latencia de 1000ms para evitar Error 429 (Límite QPS)...");
        Utilities.sleep(1000); 
      }

    } while (pageToken);

    Logger.log(`[POLICY QUERY] Extracción completada. ${this.rawPolicies.length} políticas cacheadas en memoria.`);
    return this.rawPolicies;
  }

  /**
   * Retorna las políticas de google Policy.
   */
  getPolicies() {
    return this.rawPolicies;
  }

  /**
   * Función privada que fusiona el JSON recibido de Google con los valores por defecto del registro.
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