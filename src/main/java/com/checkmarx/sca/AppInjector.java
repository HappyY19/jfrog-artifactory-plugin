package com.checkmarx.sca;

import com.checkmarx.sca.communication.AccessControlClient;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.scan.ArtifactRisksFiller;
import com.checkmarx.sca.scan.LicenseAllowanceChecker;
import com.checkmarx.sca.scan.SecurityThresholdChecker;
import com.checkmarx.sca.suggestion.PrivatePackageSuggestionHandler;
import com.google.inject.AbstractModule;

import javax.annotation.Nonnull;

import org.slf4j.Logger;

public class AppInjector extends AbstractModule {
    private final Logger _logger;
    private final ArtifactRisksFiller _artifactFiller;
    private final AccessControlClient _accessControlClient;
    private final SecurityThresholdChecker _securityThresholdChecker;
    private final LicenseAllowanceChecker _licenseAllowanceChecker;
    private final PluginConfiguration _configuration;
    private final PrivatePackageSuggestionHandler _suggestionHandler;

    public AppInjector(@Nonnull Logger logger, AccessControlClient accessControlClient, @Nonnull ArtifactRisksFiller artifactFiller, @Nonnull PluginConfiguration configuration, @Nonnull SecurityThresholdChecker securityThresholdChecker, @Nonnull LicenseAllowanceChecker licenseAllowanceChecker, @Nonnull PrivatePackageSuggestionHandler privatePackagesSuggestionHandler) {
        this._logger = logger;
        this._configuration = configuration;
        this._artifactFiller = artifactFiller;
        this._accessControlClient = accessControlClient;
        this._securityThresholdChecker = securityThresholdChecker;
        this._licenseAllowanceChecker = licenseAllowanceChecker;
        this._suggestionHandler = privatePackagesSuggestionHandler;
    }

    protected void configure() {
        this.bind(Logger.class).toInstance(this._logger);
        this.bind(ArtifactRisksFiller.class).toInstance(this._artifactFiller);
        this.bind(PluginConfiguration.class).toInstance(this._configuration);
        this.bind(SecurityThresholdChecker.class).toInstance(this._securityThresholdChecker);
        this.bind(LicenseAllowanceChecker.class).toInstance(this._licenseAllowanceChecker);
        this.bind(PrivatePackageSuggestionHandler.class).toInstance(this._suggestionHandler);
        if (this._accessControlClient != null) {
            this.bind(AccessControlClient.class).toInstance(this._accessControlClient);
        }

    }
}
