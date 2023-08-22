package com.checkmarx.sca;

import com.checkmarx.sca.communication.AccessControlClient;
import com.checkmarx.sca.configuration.ConfigurationReader;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.scan.ArtifactRisksFiller;
import com.checkmarx.sca.scan.LicenseAllowanceChecker;
import com.checkmarx.sca.scan.SecurityThresholdChecker;
import com.checkmarx.sca.suggestion.PrivatePackageSuggestionHandler;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.RepoPathFactory;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.artifactory.repo.VirtualRepositoryConfiguration;
import org.slf4j.Logger;

public class ScaPlugin {
    private final Injector _injector;
    private final Logger _logger;
    private final Repositories _repositories;

    public ScaPlugin(@Nonnull Logger logger, @Nonnull File pluginsDirectory, @Nonnull Repositories repositories) throws IOException {
        this._logger = logger;

        try {
            PluginConfiguration configuration = ConfigurationReader.loadConfiguration(pluginsDirectory, logger);
            configuration.validate();
            AccessControlClient accessControlClient = this.tryToAuthenticate(configuration, logger);
            this._repositories = repositories;
            ArtifactRisksFiller risksFiller = new ArtifactRisksFiller(repositories);
            SecurityThresholdChecker securityThresholdChecker = new SecurityThresholdChecker(repositories);
            LicenseAllowanceChecker licenseAllowanceChecker = new LicenseAllowanceChecker(repositories);
            PrivatePackageSuggestionHandler privatePackageSuggestionHandler = new PrivatePackageSuggestionHandler(repositories, configuration.hasAuthConfiguration());
            AppInjector appInjector = new AppInjector(this._logger, accessControlClient, risksFiller, configuration, securityThresholdChecker, licenseAllowanceChecker, privatePackageSuggestionHandler);
            this._injector = Guice.createInjector(new Module[]{appInjector});
        } catch (Exception var11) {
            this._logger.error("Sca plugin could not be initialized!");
            throw var11;
        }
    }

    private AccessControlClient tryToAuthenticate(@Nonnull PluginConfiguration configuration, @Nonnull Logger logger) {
        AccessControlClient accessControlClient = null;

        try {
            if (configuration.hasAuthConfiguration()) {
                accessControlClient = new AccessControlClient(configuration, logger);
                accessControlClient.Authenticate(configuration.getAccessControlCredentials());
            } else {
                this._logger.info("Authentication configuration not defined.");
            }
        } catch (Exception var5) {
            this._logger.error("Authentication failed. Working without authentication.");
        }

        return accessControlClient;
    }

    public void checkArtifactsAlreadyPresent(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        this.addPackageRisks(repoPath, nonVirtualRepoPaths);
    }

    public void checkArtifactsAlreadyPresent(RepoPath repoPath, boolean forceScan) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        this.addPackageRisks(repoPath, nonVirtualRepoPaths, forceScan);
    }

    public void checkArtifactsForSuggestionOnPrivatePackages(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        PrivatePackageSuggestionHandler suggestion = (PrivatePackageSuggestionHandler) this._injector.getInstance(PrivatePackageSuggestionHandler.class);

        for (RepoPath artifact : nonVirtualRepoPaths) {
            suggestion.suggestPrivatePackage(artifact, nonVirtualRepoPaths);
        }

    }

    public void beforeDownload(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        boolean riskAddedSuccessfully = this.addPackageRisks(repoPath, nonVirtualRepoPaths);
        if (riskAddedSuccessfully) {
            this.checkRiskThreshold(repoPath, nonVirtualRepoPaths);
            this.checkLicenseAllowance(repoPath, nonVirtualRepoPaths);
        }

    }

    public void beforeUpload(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        PrivatePackageSuggestionHandler suggestionHandler = (PrivatePackageSuggestionHandler) this._injector.getInstance(PrivatePackageSuggestionHandler.class);
        suggestionHandler.suggestPrivatePackage(repoPath, nonVirtualRepoPaths);
    }

    private ArrayList<RepoPath> getNonVirtualRepoPaths(RepoPath repoPath) {
        String repositoryKey = repoPath.getRepoKey();
        RepositoryConfiguration repoConfiguration = this._repositories.getRepositoryConfiguration(repositoryKey);
        ArrayList<RepoPath> nonVirtualRepoPaths = new ArrayList<>();
        if (repoConfiguration instanceof VirtualRepositoryConfiguration) {
            this.setNonVirtualRepoPathsRepoPathsOfVirtualRepository(nonVirtualRepoPaths, repoConfiguration, repoPath.getPath());
        } else {
            nonVirtualRepoPaths.add(repoPath);
        }

        return nonVirtualRepoPaths;
    }

    private void setNonVirtualRepoPathsRepoPathsOfVirtualRepository(@Nonnull ArrayList<RepoPath> nonVirtualRepoPaths, @Nonnull RepositoryConfiguration repoConfiguration, @Nonnull String artifactPath) {
        VirtualRepositoryConfiguration virtualConfiguration = (VirtualRepositoryConfiguration) repoConfiguration;

        for (String repo : virtualConfiguration.getRepositories()) {
            RepoPath repoPathFromVirtual = RepoPathFactory.create(repo, artifactPath);
            if (this._repositories.exists(repoPathFromVirtual)) {
                nonVirtualRepoPaths.add(repoPathFromVirtual);
            }
        }

    }

    private boolean addPackageRisks(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        try {
            String path = repoPath.getPath();
            if (path == null) {
                this._logger.error("SCA was unable to complete verification. The path was not provided.");
                return false;
            } else {
                ArtifactRisksFiller artifactChecker = (ArtifactRisksFiller) this._injector.getInstance(ArtifactRisksFiller.class);
                return artifactChecker.addArtifactRisks(repoPath, nonVirtualRepoPaths);
            }
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete verification of: %s.\nException message: %s", repoPath.getName(), var5.getMessage()));
            return false;
        }
    }

    private boolean addPackageRisks(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths, boolean forceScan) {
        try {
            String path = repoPath.getPath();
            if (path == null) {
                this._logger.error("SCA was unable to complete verification. The path was not provided.");
                return false;
            } else {
                ArtifactRisksFiller artifactChecker = (ArtifactRisksFiller) this._injector.getInstance(ArtifactRisksFiller.class);
                return artifactChecker.addArtifactRisks(repoPath, nonVirtualRepoPaths, forceScan);
            }
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete verification of: %s.\nException message: %s", repoPath.getName(), var5.getMessage()));
            return false;
        }
    }

    private void checkRiskThreshold(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        try {
            SecurityThresholdChecker thresholdChecker = (SecurityThresholdChecker) this._injector.getInstance(SecurityThresholdChecker.class);
            thresholdChecker.checkSecurityRiskThreshold(repoPath, nonVirtualRepoPaths);
        } catch (CancelException var4) {
            this._logger.info(String.format("The download was blocked by security threshold configuration. Artifact Name: %s", repoPath.getName()));
            throw var4;
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete the security risk threshold verification for the Artifact: %s.\nException: %s", repoPath.getName(), var5));
        }

    }

    private void checkLicenseAllowance(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        try {
            LicenseAllowanceChecker licenseAllowanceChecker = (LicenseAllowanceChecker) this._injector.getInstance(LicenseAllowanceChecker.class);
            licenseAllowanceChecker.checkLicenseAllowance(repoPath, nonVirtualRepoPaths);
        } catch (CancelException var4) {
            this._logger.info(String.format("The download was blocked by license allowance configuration. Artifact Name: %s", repoPath.getName()));
            throw var4;
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete the license allowance verification for the Artifact: %s.\nException: %s", repoPath.getName(), var5));
        }

    }
}
