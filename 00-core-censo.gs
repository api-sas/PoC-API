/**
 * Wrapper de estado global para el censo de usuarios.
 * Descarga y consolida la topología de la organización para evitar 
 * consultas repetitivas a la API y sortear las limitaciones de memoria de Apps Script.
 */
class CensusStateWrapper {
  constructor() {
    this.props = PropertiesService.getScriptProperties();
    // Límite seguro por debajo de los 9KB de PropertiesService
    this.CHUNK_SIZE = 8000; 
    this.PREFIX = "CENSUS_CHUNK_";
    this.TOTAL_CHUNKS_KEY = "CENSUS_TOTAL_CHUNKS";
  }

  /**
   * Orquesta la descarga de usuarios, grupos y licencias, y guarda el resultado fragmentado.
   * @param {AuthService} authService - Instancia para obtener tokens si se usa UrlFetchApp directo.
   * @param {string} customerId - ID del cliente (ej. 'my_customer').
   */
  buildAndStoreCensus(authService, customerId) {
    Logger.log("Iniciando la construcción del censo global...");
    
    // 1. Extraer todos los usuarios (Recomendación: usar AdminDirectory avanzado para velocidad)
    const users = this._fetchAllUsers(customerId);
    
    const censoCompleto = [];

    // 2. Enriquecer cada usuario con grupos y licencias
    for (const user of users) {
      // Nota: En producción masiva, buscar extraer grupos y licencias en bulk.
      const userGroups = this._fetchUserGroups(user.primaryEmail);
      const userLicenses = this._fetchUserLicenses(user.id);
      
      censoCompleto.push({
        id: user.id,
        email: user.primaryEmail,
        orgUnitPath: user.orgUnitPath,
        groups: userGroups, // Array de strings (group_ids)
        licenses: userLicenses // Array de strings (sku_ids)
      });
    }

    // 3. Serializar y fragmentar
    this._chunkAndSave(censoCompleto);
    Logger.log(`Censo construido y almacenado con éxito: ${censoCompleto.length} usuarios procesados.`);
  }

  /**
   * Recupera los fragmentos de PropertiesService, los une y los deserializa.
   * @returns {Array} Matriz de objetos de usuario con sus atributos.
   */
  getCensus() {
    const totalChunksStr = this.props.getProperty(this.TOTAL_CHUNKS_KEY);
    if (!totalChunksStr) {
      Logger.log("No se encontró un censo almacenado.");
      return null;
    }

    const totalChunks = parseInt(totalChunksStr, 10);
    let jsonString = "";

    for (let i = 0; i < totalChunks; i++) {
      const chunk = this.props.getProperty(`${this.PREFIX}${i}`);
      if (chunk) {
        jsonString += chunk;
      }
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      Logger.log("Error al deserializar el censo: " + e.message);
      return null;
    }
  }

  /**
   * Limpia el censo de la memoria para liberar espacio en PropertiesService.
   */
  clearCensus() {
    const totalChunksStr = this.props.getProperty(this.TOTAL_CHUNKS_KEY);
    if (totalChunksStr) {
      const totalChunks = parseInt(totalChunksStr, 10);
      for (let i = 0; i < totalChunks; i++) {
        this.props.deleteProperty(`${this.PREFIX}${i}`);
      }
      this.props.deleteProperty(this.TOTAL_CHUNKS_KEY);
      Logger.log("Censo global borrado de la memoria.");
    }
  }

  // ==========================================
  // MÉTODOS PRIVADOS DE LÓGICA Y FRAGMENTACIÓN
  // ==========================================

  _chunkAndSave(dataArray) {
    // Limpiamos memoria anterior por seguridad
    this.clearCensus(); 

    const jsonString = JSON.stringify(dataArray);
    const totalLength = jsonString.length;
    let chunksCount = 0;

    for (let i = 0; i < totalLength; i += this.CHUNK_SIZE) {
      const chunk = jsonString.substring(i, i + this.CHUNK_SIZE);
      this.props.setProperty(`${this.PREFIX}${chunksCount}`, chunk);
      chunksCount++;
    }

    this.props.setProperty(this.TOTAL_CHUNKS_KEY, chunksCount.toString());
  }

  // --- Mock/Wrappers de llamadas a la API (Admin SDK) ---

  _fetchAllUsers(customerId) {
    // AdminDirectory.Users.list({customer: customerId, maxResults: 500})
    // Para simplificar, devolvemos una estructura esperada:
    return AdminDirectory.Users.list({
      customer: customerId,
      maxResults: 500,
      projection: "basic"
    }).users || [];
  }

  _fetchUserGroups(userEmail) {
    // Retorna lista de IDs de los grupos a los que pertenece el usuario
    try {
      const response = AdminDirectory.Groups.list({ userKey: userEmail });
      return (response.groups || []).map(g => g.id);
    } catch (e) {
      return [];
    }
  }

  _fetchUserLicenses(userId) {
    // Funciona con la API Enterprise License Manager en Advanced Services.
    // Retorna los SKU IDs asignados al usuario usando el API de Licencias
    try {
      const productId = "Google-Apps"; // O el producto pertinente
      const response = AdminLicenseManager.LicenseAssignments.listForProduct(productId, userId);
      return (response.items || []).map(item => item.skuId);
    } catch (e) {
      return [];
    }
  }
}