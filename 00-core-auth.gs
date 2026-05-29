/**
 * Se encarga de proveer y gestionar la identidad, permisos y tokens de acceso.
 * Centraliza tanto el token interactivo del usuario como el token firmado 
 * por Cuenta de Servicio con Delegación de Dominio (DWD).
 */
class AuthService {
  constructor() {
    this.cache = CacheService.getScriptCache();
    
    // Almacenamos el JSON de la cuenta de servicio de forma estructurada
    this.saCredentials = {
      "type": "service_account",
      "project_id": "poc2-495720",
      "private_key_id": "927ab5e9606402ab071657103fb0dd6350b2a010",
      "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQD4d9t/2mKQrrwR\nXD6xyVSfIvgFZ0fOqKCpo6U6Zbzrsk896sOhD0ykDxVN3Wh3t0xMwA9U1gKckduM\n1Kwuv9osjLH/PFV2pZyUwDxl3v2bgK0zH/DWnCG+nWmsdZJjYSi1MzqEXZ0PuHYi\nSC7oHHxDZBpU1vQGK1vZWqxy2EZ8LjrZBKk6bsqsvg23HamdNv5QT5f64c5wOpc8\nxXyI+pjjLBKWL9RhIu637+rawoCF64jACURtDbPYZ/7NCmNL3xXs0OTObXTIOD2R\nuYoUQSYXJ8ideioZy5aeUIYzAIjoZYFfOmBxzGprrpqmNYtx76Q+trFSHvu/tSLi\n2xlSAOYfAgMBAAECggEAJrvEj49TSzu6HLi1G1EH7JDueiUqGAjIlvloUgy3IUUY\nPk5BNfPlHjQtvYg092ivL83G9hIwsQi54Z/rwZPt5oD+ZIwaxJa3rKa1I6pZ/apX\nFb+2czY+unDenuBrNCvaxTiZuDXBvMgkPl7jVRLPuk+6HRyvSODsfhs5A+Q8RLI/\nnQIeD9lzVdJHZQt9ViOqYqKE/SFq8WJzaXoF5VEBgEa1JJCjBA4lOt3199Uo9/GU\nQ+tC+rgGRybcuHimEDD5JLu+areO312s3f037Qhd105BHq2jRWPL+CPXWCg3mAKy\ Ey+ocunIVHcoBpoDgMGwmuCjezq/HEaYs1l+a3x2DQKBgQD/2nuUId9ctsmiOK3b\nMIXKyWBnT6rzctWNjRlnkhs88zexiIe7HflyC663pOME8UShpYR5LZBZHXV5xZ4o\nemm3YMyvdJXYppKLb4rjhO0PRS/a49jCs+uSAnob3jIWeef97cr9Trg9Gqh476v8\nI5d+/kBohn0NP8AcnfPiYUbDnQKBgQD4nEqv/V9gjFWjOehJKmCg1TqY+rySrcbx\nTp0TXVwzP9hhHyb85Hc4hCIB8KX+RyxHUw9wjYf6l7zv91BnDHfN1a0BKDqfVAL6\npVTAsEWSTJwrflm6aatpzhhaxUaHX7yX9KSUuVr7wlJhxB4V5UkwjRG7bJ8N1WxP\ns5b/sGUZ6wKBgDn5RbtBGZ2mhXXOpgZerlJO4xtFwBS91onmiPUg9C8RZXNC3o6V\nsioXX5WZNR+vk7+VA7l5i5XFyRK4pqfBZSb6NicjobifteEGe1AmlJi7MqbErh8g\nKabCDO03od3Z7alqMm7HYZPm8HnGxQ+y+Ob7sZh9sORJp7xURijrpd85AoGAKsNv\nkXAq3Mem32nRi+xPLLsg1jmjADQGGXHlUPRpLKOZy7L5GN0PqNgJpX3If8GsWyRt\nbnXZ4wAAzuIioWcioHRVyvIpi0h/LrALsQ1hGjY1UsHsG0Wb55o81DhE1npgTV8W\nhEKR5OZbF1gNuMR033YUi8G2ZkHE3LzOh3LHITsCgYBmRd6RW/4vHjlO/jU+Iy18\nUtBS801hhUMjFawK8gL7yxoQq9cCk6eyXIXQ6C1wNsIXHqh+fGPC+GAnkn8IF9Oo\n/bz6QPwhPsmxXxDWbUOssuWHOSMWb8OAnvFS3drq4FaPxnHrHTdeKmeT+vq2rifm\nOcZ2c1jAYj37I9ym071dOQ==\n-----END PRIVATE KEY-----\n",
      "client_email": "auditoria-test@poc2-495720.iam.gserviceaccount.com",
      "token_uri": "https://oauth2.googleapis.com/token"
    };
  }

  /**
   * Token interactivo estándar de Apps Script (Contexto de usuario ejecutor)
   */
  getToken() {
    return ScriptApp.getOAuthToken();
  }

  getAuthHeader() {
    return { "Authorization": "Bearer " + this.getToken() };
  }

  /**
   * NUEVO: Genera u obtiene del caché un token firmado por Cuenta de Servicio
   * aplicando Delegación de Dominio Completo (DWD) para suplantar a un Súper Admin.
   * * @param {string} adminEmail Correo electrónico del Súper Administrador a suplantar.
   * @param {Array<string>} scopes Arreglo de alcances de Google exigidos.
   * @return {Object} Cabecera de autenticación estructurada para UrlFetchApp.
   */
  getPrivilegedAuthHeader(adminEmail, scopes = ["https://www.googleapis.com/auth/cloud-identity.policies.readonly"]) {
    const cacheKey = "SA_TOKEN_" + adminEmail.replace(/[^a-zA-Z0-9]/g, "");
    let token = this.cache.get(cacheKey);

    if (token) {
      return { "Authorization": "Bearer " + token };
    }

    Logger.log(`[AUTH] Generando nuevo token de acceso privilegiado vía DWD para: ${adminEmail}`);
    
    // 1. Construcción del Header del JWT
    const jwtHeader = JSON.stringify({ alg: "RS256", typ: "JWT" });
    
    // 2. Construcción del Claim Set (Payload) incluyendo la suplantación ('sub')
    const now = Math.floor(Date.now() / 1000);
    const jwtClaim = JSON.stringify({
      iss: this.saCredentials.client_email,
      sub: adminEmail, // Clave de la suplantación de identidad (DWD)
      scope: scopes.join(" "),
      aud: this.saCredentials.token_uri,
      exp: now + 3600, // Expiración máxima de 1 hora
      iat: now
    });

    // 3. Codificación WebSafe Base64 nativa de Google Apps Script
    const base64Header = Utilities.base64EncodeWebSafe(jwtHeader).replace(/=+$/, '');
    const base64Claim = Utilities.base64EncodeWebSafe(jwtClaim).replace(/=+$/, '');
    const signatureInput = base64Header + "." + base64Claim;

    // 4. Firma criptográfica RSA-SHA256 usando la llave privada del JSON
    const signatureBytes = Utilities.computeRsaSha256Signature(signatureInput, this.saCredentials.private_key);
    const base64Signature = Utilities.base64EncodeWebSafe(signatureBytes).replace(/=+$/, '');

    const jwtAssertion = signatureInput + "." + base64Signature;

    // 5. Transacción POST hacia el servidor de tokens de Google
    const options = {
      method: "post",
      contentType: "application/x-www-form-urlencoded",
      payload: {
        grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
        assertion: jwtAssertion
      },
      muteHttpExceptions: true
    };

    try {
      const response = UrlFetchApp.fetch(this.saCredentials.token_uri, options);
      const resJson = JSON.parse(response.getContentText());

      if (resJson.error) {
        throw new Error(`Google OAuth rechazó el JWT: ${resJson.error_description || resJson.error}`);
      }

      token = resJson.access_token;
      
      // Guardamos en caché por 55 minutos (3300 segundos) para mitigar llamadas redundantes
      this.cache.put(cacheKey, token, 3300); 
      
      return { "Authorization": "Bearer " + token };

    } catch (e) {
      Logger.log(`[CRÍTICO - AUTH] Error en intercambio criptográfico de Cuenta de Servicio: ${e.message}`);
      throw e;
    }
  }

  // Métodos de conveniencia preexistentes
  getDomain() { return "test.apisas.com"; }
  getCurrentUserEmail() { return Session.getActiveUser().getEmail(); }
  getZeroTrustPolicyId() { return "accessPolicies/1028743991591"; }
  getCustomerId() { return "my_customer"; }
  getGcpProjectId() { return this.saCredentials.project_id; }
  getGcpServiceAccountEmail() { return this.saCredentials.client_email; }
  
  // ... [Mantenemos el resto de tus mapas de roles exactamente igual] ...
}