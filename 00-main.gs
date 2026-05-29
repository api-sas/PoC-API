/**
 * Orquestador principal para la auditoría de Identidad y Autenticación
 */

function AuditoriaIdentidadIdentificacion() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    // OAuth config
    const userEmail = auth.getCurrentUserEmail();
    const authHeader = auth.getAuthHeader();
    const zeroTrustPolicyId = auth.getZeroTrustPolicyId();
    const customerId = auth.getCustomerId();
    //censo de usuarios para policy query
    const censoWrapper = new CensusStateWrapper();
    censoWrapper.buildAndStoreCensus(auth, customerId);
    const censo = censoWrapper.getCensus();
    const policyQuery = new GlobalPolicyExtractor(auth, customerId);
    const politicas = policyQuery.fetchTree();
    const globalContext = {
      census: censo,
      policies: politicas
    };
    const auditor = new SecurityAuditorFacade(auth, globalContext);

    // 1. Instanciamos las estrategias en un arreglo local para retener su referencia
    const estrategias = [
      new SsoAuditStrategy(customerId),
      new StrongPasswordPolicyStrategy(customerId),//5

      /**
      

      new TwoStepVerificationCounter(), //10
      new EmployeeIdStrategy(), //22
      new UsuarioConfiguracionAvanzadaStrategy(), //25
      new SuperAdminSecurityStrategy(), //26
      new ContextAwareAccessStrategy(zeroTrustPolicyId), //27
      new ExternalProvisioningStrategy(), //30
      new ManualUserAuditStrategy() //31

      
      new AuditTokens(userEmail), //7, 8
      new PasswordManagerStrategy(), //17
      new DeprovisioningAuditStrategy(), //32
      new SlaOffboardingAuditStrategy(), //22
      new SecurityAlertsAuditStrategy(), //34
      new GroupExposureAuditStrategy(authHeader),//35
      new AdvancedProtectionPolicyStrategy(customerId), //24
      new PasswordReusePolicyStrategy(customerId), //6
      new TwoStepVerificationEnrollmentPolicyStrategy(customerId), //9
      new TwoStepVerificationEnforcementPolicyStrategy(customerId), //11
      new AdminTwoStepVerificationEnforcementStrategy(customerId), //12
      new TrustedDevice2SVPolicyStrategy(customerId), //13
      new Allowed2SVMethodsPolicyStrategy(customerId), //14
      new GracePeriod2SVPolicyStrategy(customerId), //15
      new TwoStepVerificationSignInCodePolicyStrategy(customerId), // 16
      new SuperAdminAccountRecoveryPolicyStrategy(customerId), //18
      new UserAccountRecoveryPolicyStrategy(customerId), //19
      new PostSsoLoginPolicyStrategy(customerId), //20
      new EmployeeIdLoginChallengePolicyStrategy(customerId), //21
      */ 
      

    ];
  // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de identidad y autenticación, puede tomar algunos segundos"), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade ahora se encarga de pausar automáticamente)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de identidad y autenticación completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}
  
/**
 * Orquestador principal para la auditoría de Administración
 */
function AuditoriaAdministracion() {
  const ui = SpreadsheetApp.getUi();
  try {
    const auth = new AuthService();
    const auditor = new SecurityAuditorFacade(auth);
    const customerId = auth.getCustomerId();
    const superAdminRoleId = auth.getSuperAdminRoleId(); 
    const groupsAdminRoleId = auth.getGroupsAdminRoleId();
    const userAdminRoleId = auth.getUserAdminRoleId();
    const helpDeskRoleId = auth.getHelpDeskAdminRoleId();
    const androidAdminRoleId = auth.getAndroidAdminRoleId();
    const voiceAdminRoleId = auth.getVoiceAdminRoleId();
    const mobileAdminRoleId = auth.getMobileAdminRoleId();
    const servicesAdminRoleId = auth.getServicesAdminRoleId();

    // 1. Instanciamos las estrategias exclusivas de Administración
    const estrategias = [
      new SuperAdminRoleAssignmentStrategy(customerId, superAdminRoleId), // Celda G39
      new GroupsAdminRoleAssignmentStrategy(customerId, groupsAdminRoleId),
      new UserManagementAdminRoleStrategy(customerId, userAdminRoleId),
      new HelpDeskAdminRoleStrategy(customerId, helpDeskRoleId),
      new AndroidAdminRoleStrategy(customerId, androidAdminRoleId),
      new GoogleVoiceAdminRoleStrategy(customerId, voiceAdminRoleId),
      new MobileAdminRoleStrategy(customerId, mobileAdminRoleId),
      new ServicesAdminRoleStrategy(customerId, servicesAdminRoleId),
      new VaultServiceStatusStrategy(customerId)

    ];

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de administración, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de administración completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de administración: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}

/**
 * Orquestador principal para la auditoría de Aplicaciones Externas (OAuth, Marketplace, etc.)
 */
function AuditoriasAppsExternas() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    const auditor = new SecurityAuditorFacade(auth);
    
    // Extracción de variables comunes que podríamos necesitar
    const customerId = auth.getCustomerId();
    const authHeader = auth.getAuthHeader();
    const gcpProjectId = auth.getGcpProjectId();
    const gcpServiceAccount = auth.getGcpServiceAccountEmail();

    // 1. Instanciamos las estrategias exclusivas de Apps Externas
    const estrategias = [
      new GoogleServicesApiControlStrategy(customerId),
      new GoogleCloudApiControlStrategy(customerId),
      new UnconfiguredAppsStrategy(customerId),
      new InternalAppsTrustStrategy(customerId),
      new CustomUserMessageApiStrategy(customerId),
      new DwdTokenRequestAuditStrategy(),
      new ServiceAccountKeyAgeStrategy(gcpProjectId, gcpServiceAccount),
      new MarketplaceInstallPolicyStrategy(customerId),
      new AdminAppInstallEventStrategy(),
      new MarketplaceAllowlistStrategy(customerId)
    ];

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    // Si no hay estrategias aún, avisamos y salimos para no ejecutar en vacío
    if (estrategias.length === 0) {
      ui.alert("El módulo de Aplicaciones Externas está listo, pero aún no tiene métricas asignadas.");
      return;
    }

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de aplicaciones externas, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de aplicaciones externas completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de apps externas: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}

/**
 * Orquestador principal para la auditoría de configuraciones de Correo Electrónico (Gmail)
 */
function AuditoriasEmail() {
  const ui = SpreadsheetApp.getUi();
  
  try {
    const auth = new AuthService();
    const auditor = new SecurityAuditorFacade(auth);
    
    // Extracción de variables comunes que podríamos necesitar
    const customerId = auth.getCustomerId();
    const domain = auth.getDomain();
    // const authHeader = auth.getAuthHeader(); 

    // 1. Instanciamos las estrategias exclusivas de Correo Electrónico
    const estrategias = [
      
      new GmailConfidentialModeStrategy(customerId),
      new GmailImapAccessStrategy(customerId),
      new WorkspaceSyncForOutlookStrategy(customerId),
      new GmailAutoForwardingStrategy(customerId),
      new GmailImageProxyBypassStrategy(customerId),
      new GmailPerUserOutboundGatewayStrategy(customerId),
      new GmailLinksAndExternalImagesStrategy(customerId),
      new GmailAttachmentSafetyStrategy(customerId),
      new GmailSpoofingAndAuthenticationStrategy(customerId),
      new GmailAttachmentSafetyId073Strategy(customerId),
      new GmailSpamFilterIpAllowlistStrategy(customerId),
      new GmailSpamOverrideListsStrategy(customerId),
      new GmailEnhancedPreDeliveryScanningStrategy(customerId),
      new GmailBlockedSenderListsStrategy(customerId),
      new GmailLinksExternalImagesSecurityStrategy(customerId),
      new GmailContentComplianceStrategy(customerId),
      new GmailAttachmentComplianceStrategy(customerId),
      new TestDomainAliasStrategy(customerId),
      new SpfRecordAuditStrategy(domain),
      new DkimRecordAuditStrategy(domain),
      new DmarcRecordAuditStrategy(domain),
      new MtaStsRecordAuditStrategy(domain)

    ];

    // 2. Agregamos las estrategias al auditor
    estrategias.forEach(estrategia => auditor.addStrategy(estrategia));

    // Si no hay estrategias aún, avisamos y salimos para no ejecutar en vacío
    if (estrategias.length === 0) {
      ui.alert("El módulo de Correo Electrónico está listo, pero aún no tiene métricas asignadas.");
      return;
    }

    ui.showModelessDialog(HtmlService.createHtmlOutput("⏳ Procesando auditoría de correo electrónico, puede tomar algunos segundos..."), "Estado");
    
    // 3. Ejecutamos las APIs (La Facade se encarga de pausar automáticamente para proteger la cuota)
    const resultados = auditor.ejecutarTodo();
    
    // 4. Bucle Polimórfico Puro para escribir en el Sheets
    resultados.forEach(res => {
      const estrategiaResponsable = estrategias.find(e => e.name === res.name);
      
      if (estrategiaResponsable && res) {
        estrategiaResponsable.writeToSheet(res); 
      }
    });
    generarResumenSemaforo();
    ui.alert("✅ Auditoría de correo electrónico completada con éxito.");

  } catch (error) {
    Logger.log("Error en auditoría de email: " + error.stack);
    ui.alert("❌ Error: " + error.message);
  }
}