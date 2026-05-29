/**
 * Analizador local de expresiones MIN y MAX
 * Evalúa si una política de Google Workspace aplica a un usuario específico
 * basándose en su Unidad Organizativa, Grupos y Licencias.
 */
class CELParserEngine {
  /**
   * Evalúa la condición de una política contra los datos de un usuario.
   * @param {string} query - (ej. "entity.groups.exists(...) && !entity.licenses.exists(...)").
   * @param {Object} user - usuario extraído del CensusStateWrapper.
   * @returns {boolean} True si la política aplica al usuario, False si no.
   */
  static evaluate(query, user) {
    // 1. Regla raíz: Si la regla no tiene condiciones (query vacío), 
    // significa que aplica a toda la empresa. ¡Aplica a Juan!
    if (!query || query.trim() === "" || query.includes("customer==")) {
      // Si tiene más condiciones, debemos seguir evaluando.
      if (!query.includes("entity.")) return true;
    }

    let isApplicable = false;

    // 2. (OUs): itera en cada UO y busca al usuario
    // si el usuario y la UO entonces: isApplicable= True
    if (query.includes("entity.org_units.exists")) {
      const ouMatches = this._extractArrayValues(query, "org_units");
      if (ouMatches.some(ou => user.orgUnitPath && user.orgUnitPath.includes(ou))) {
         isApplicable = true;
      }
    }

    // 3. Evaluamos la pertenencia a Grupos
    if (query.includes("entity.groups.exists")) {
      const groupMatches = this._extractArrayValues(query, "groups");
      const userGroups = user.groups || [];
      if (groupMatches.some(gId => userGroups.includes(gId))) {
        isApplicable = true;
      }
    }

    // 4. Si el usuario tiene una licencia exclusiva retorna false.
    // Ejemplo: Eximir a usuarios con licencia Gemini Enterprise de ciertas restricciones
    if (query.includes("!entity.licenses.exists")) {
      const excludedLicenses = this._extractArrayValues(query, "licenses");
      const userLicenses = user.licenses || [];
      // Si el usuario TIENE una licencia que está en la lista de exclusión, la política se anula
      if (excludedLicenses.some(sku => userLicenses.includes(sku))) {
        return false; // La exclusión gana inmediatamente
      }
    } 
    else if (query.includes("entity.licenses.exists")) {
      const requiredLicenses = this._extractArrayValues(query, "licenses");
      const userLicenses = user.licenses || [];
      
      if (requiredLicenses.some(sku => userLicenses.includes(sku))) {
        isApplicable = true;
      } else {
        return false; // Si requiere la licencia y no la tiene, no aplica
      }
    }

    return isApplicable;
  }

  /**
   * Función para extraer los IDs dentro de los corchetes dentro del regex.
   * Extrae valores de fragmentos como: group in ['id1', 'id2']
   */
  static _extractArrayValues(query, entityType) {
    // Esta expresión regular busca bloques [ ... ] cerca de la entidad solicitada
    const regex = new RegExp(`entity\\.${entityType}\\.exists[^\\]]*\\[([^\\]]+)\\]`);
    const match = query.match(regex);
    
    if (match && match[1]) {
      // Limpia comillas simples, dobles y espacios en blanco, devolviendo un arreglo limpio
      return match[1].replace(/['"]/g, "").split(",").map(s => s.trim());
    }
    return [];
  }
}

/**
 * Reductores: Emula el comportamiento matemático de los servidores de Google para 
 * decidir qué política gana cuando hay un conflicto (ej. un usuario con múltiples políticas).
 */
class PolicyReducerFactory {
  /**
   * Toma un arreglo de políticas aplicables y las reduce a una sola decisión.
   * @param {Array} applicablePolicies - Arreglo de políticas que pasaron el CELParserEngine.
   * @param {string} settingType - El tipo de configuración (ej. "security.password").
   * @returns {Object|null} La política ganadora.
   */
  static reduce(applicablePolicies, settingType) {
    // si el usuario no tiene una regla, retorna null
    if (!applicablePolicies || applicablePolicies.length === 0) {
      return null;
    }
    
    if (applicablePolicies.length === 1) {
      // si el usuario solo tiene una regla, retorna la misma
      return applicablePolicies[0];
    }

    // Estrategia de Reducción dinámica
    // Dependiendo del tipo de política, Google usa diferentes algoritmos.
    switch (settingType) {
      case "security.password":
      case "security.lessSecureApps":
        // REDUCTOR "MAX": Gana la política con el 'sortOrder' más alto (Precedencia absoluta)
        return this._maxReducer(applicablePolicies);
        
      // Aquí se pueden agregar otros reductores en el futuro (ej. List, MergeMap)
      // case "dlp.rules": return this._listReducer(applicablePolicies);
        
      default:
        // Por seguridad, el reductor más común es "Max"
        return this._maxReducer(applicablePolicies);
    }
  }

  /**
   * Implementación del Reductor Max: Gana la política con el 'sortOrder' más alto.
   */
  static _maxReducer(policies) {
    return policies.reduce((prev, current) => {
      // Aseguramos que sortOrder sea un número. Si no existe, vale 0.
      const prevOrder = parseInt(prev.sortOrder || 0, 10);
      const currOrder = parseInt(current.sortOrder || 0, 10);    
      return (prevOrder >= currOrder) ? prev : current;
    });
  }
  /**
   * Implementación del Reductor Merge: Combina múltiples objetos en uno solo.
   * Las políticas con mayor 'sortOrder' sobrescriben las propiedades de las menores.
   */
  static _mergeReducer(policies) {
    // 1. Ordenamos de menor a mayor prioridad (sortOrder).
    const sorted = policies.slice().sort((a, b) => {
      return parseInt(a.sortOrder || 0, 10) - parseInt(b.sortOrder || 0, 10);
    });
    // 2. Fusionamos las configuraciones
    let mergedSetting = {};
    for (const policy of sorted) {
       if (policy.setting) {
         // Fusión superficial de objetos
         mergedSetting = { ...mergedSetting, ...policy.setting };
       }
    }
    // Retornamos un objeto simulado que representa la política final fusionada
    return {
      setting: mergedSetting,
      _mergedFrom: sorted.length // Telemetría: útil para depurar
    };
  }

  /**
   * Reductor List: Concatena arreglos de múltiples políticas.
   */
  static _listReducer(policies) {
    // 1. Ordenamos de menor a mayor prioridad.
    const sorted = policies.slice().sort((a, b) => {
      return parseInt(a.sortOrder || 0, 10) - parseInt(b.sortOrder || 0, 10);
    });
    // 2. Acumulamos las listas (Asumiremos que los datos viven en un arreglo genérico, ej. 'items')
    let combinedList = [];
    for (const policy of sorted) {
       if (policy.setting) {
         // Buscamos dinámicamente cualquier arreglo dentro de la configuración
         for (const key in policy.setting) {
           if (Array.isArray(policy.setting[key])) {
             combinedList = combinedList.concat(policy.setting[key]);
           }
         }
       }
    }

    return {
      setting: { combinedItems: combinedList },
      _combinedFrom: sorted.length
    };
  }
}