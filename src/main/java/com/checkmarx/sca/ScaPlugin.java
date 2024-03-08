package com.checkmarx.sca;

import com.checkmarx.sca.communication.AccessControlClient;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.ConfigurationReader;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.models.ArtifactId;
import com.checkmarx.sca.models.PackageInfo;
import com.checkmarx.sca.scan.ArtifactRisksFiller;
import com.checkmarx.sca.scan.LicenseAllowanceChecker;
import com.checkmarx.sca.scan.SecurityThresholdChecker;
import com.checkmarx.sca.suggestion.PrivatePackageSuggestionHandler;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Module;
import com.fasterxml.jackson.dataformat.csv.CsvMapper;
import com.fasterxml.jackson.dataformat.csv.CsvSchema;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.MappingIterator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import java.util.ArrayList;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;

import org.artifactory.repo.Repositories;

import org.slf4j.Logger;

public class ScaPlugin {
    private final Injector _injector;
    private final Logger _logger;
    private final Repositories _repositories;

    public ScaPlugin(@Nonnull Logger logger, @Nonnull File pluginsDirectory, @Nonnull Repositories repositories)
            throws IOException, URISyntaxException {
        this._logger = logger;

        try {
            PluginConfiguration configuration = ConfigurationReader.loadConfiguration(pluginsDirectory, logger);
            configuration.validate();
            AccessControlClient accessControlClient = this.tryToAuthenticate(configuration, logger);
            this._repositories = repositories;
            ArtifactRisksFiller risksFiller = new ArtifactRisksFiller(repositories);

            File tempFile = new File(ScaPlugin.class.getProtectionDomain().getCodeSource().getLocation()
                    .toURI());
            String filePath = tempFile.getParentFile().getPath();
            this._logger.debug(String.format("file path: %s", filePath));
            ArrayList<PackageInfo> packageBlackList = this.getPackagesList(filePath + "/package_black_list.csv");
            ArrayList<PackageInfo> packageWhiteList = this.getPackagesList(filePath + "/package_white_list.csv");
            SecurityThresholdChecker securityThresholdChecker = new SecurityThresholdChecker(repositories,
                    packageBlackList, packageWhiteList);
            LicenseAllowanceChecker licenseAllowanceChecker = new LicenseAllowanceChecker(repositories);
            PrivatePackageSuggestionHandler privatePackageSuggestionHandler = new PrivatePackageSuggestionHandler(
                    repositories, configuration.hasAuthConfiguration());
            AppInjector appInjector = new AppInjector(this._logger, accessControlClient, risksFiller, configuration,
                    securityThresholdChecker, licenseAllowanceChecker, privatePackageSuggestionHandler);
            this._injector = Guice.createInjector(new Module[]{appInjector});
        } catch (Exception var11) {
            this._logger.error("Sca plugin could not be initialized!");
            throw var11;
        }
    }

    private ArrayList<PackageInfo> getPackagesList(String packageBlacklistCsvPath) {
        ArrayList<PackageInfo> result = new ArrayList<>();
        File csvFile = new File(packageBlacklistCsvPath);
        CsvMapper csvMapper = new CsvMapper();
        CsvSchema schema = CsvSchema.emptySchema().withHeader();
        ObjectReader oReader = csvMapper.readerFor(PackageInfo.class).with(schema);

        try (MappingIterator<PackageInfo> mi = oReader.readValues(csvFile)) {
            while (mi.hasNext()) {
                PackageInfo current = mi.next();
                result.add(current);
                this._logger.debug(current.toString());
            }
        } catch (Exception e) {
            this._logger.error(String.format("Error during read csv file, %s", e));
        }
        this._logger.debug(String.format("number of result: %d", result.size()));
        return result;
    }

    private AccessControlClient tryToAuthenticate(@Nonnull PluginConfiguration configuration, @Nonnull Logger logger) {
        AccessControlClient accessControlClient = null;

        try {
            if (configuration.hasAuthConfiguration()) {
                accessControlClient = new AccessControlClient(configuration, logger);
                accessControlClient.Authenticate(configuration.getAccessControlCredentials());
            } else {
                this._logger.debug("Authentication configuration not defined.");
            }
        } catch (Exception var5) {
            this._logger.error("Authentication failed. Working without authentication.");
        }

        return accessControlClient;
    }

    public void checkArtifactsAlreadyPresent(RepoPath repoPath) {
        this.checkArtifactsAlreadyPresent(repoPath, false);
    }

    public void checkArtifactsAlreadyPresent(RepoPath repoPath, boolean forceScan) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        this.addPackageRisks(repoPath, nonVirtualRepoPaths, forceScan);
    }

    public void checkArtifactsForSuggestionOnPrivatePackages(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        PrivatePackageSuggestionHandler suggestion = (PrivatePackageSuggestionHandler) this._injector.getInstance(
                PrivatePackageSuggestionHandler.class);

        for (RepoPath artifact : nonVirtualRepoPaths) {
            suggestion.suggestPrivatePackage(artifact, nonVirtualRepoPaths);
        }

    }

    public void beforeDownload(RepoPath repoPath) {
        this.beforeDownload(repoPath, false);
    }

    public void beforeDownload(RepoPath repoPath, boolean disableBlock) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        boolean riskAddedSuccessfully = this.addPackageRisks(repoPath, nonVirtualRepoPaths);
        if (!disableBlock && riskAddedSuccessfully) {
            this.checkRiskThreshold(repoPath, nonVirtualRepoPaths);
            this.checkLicenseAllowance(repoPath, nonVirtualRepoPaths);
        }
    }

    public void beforeUpload(RepoPath repoPath) {
        ArrayList<RepoPath> nonVirtualRepoPaths = this.getNonVirtualRepoPaths(repoPath);
        PrivatePackageSuggestionHandler suggestionHandler = (PrivatePackageSuggestionHandler) this._injector
                .getInstance(PrivatePackageSuggestionHandler.class);
        suggestionHandler.suggestPrivatePackage(repoPath, nonVirtualRepoPaths);
    }

    private ArrayList<RepoPath> getNonVirtualRepoPaths(RepoPath repoPath) {
        ArtifactRisksFiller artifactChecker = (ArtifactRisksFiller) this._injector
                .getInstance(ArtifactRisksFiller.class);
        return artifactChecker.getNonVirtualRepoPaths(repoPath);
    }

    private boolean addPackageRisks(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        return this.addPackageRisks(repoPath, nonVirtualRepoPaths, false);
    }

    private boolean addPackageRisks(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths,
                                    boolean forceScan) {
        try {
            String path = repoPath.getPath();
            if (path == null) {
                this._logger.error("SCA was unable to complete verification. The path was not provided.");
                return false;
            } else {
                ArtifactRisksFiller artifactChecker = (ArtifactRisksFiller) this._injector
                        .getInstance(ArtifactRisksFiller.class);
                return artifactChecker.addArtifactRisks(repoPath, nonVirtualRepoPaths, forceScan);
            }
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete verification of: %s.\nException message: %s",
                    repoPath.getName(), var5.getMessage()));
            return false;
        }
    }

    private void checkRiskThreshold(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        try {
            SecurityThresholdChecker thresholdChecker = (SecurityThresholdChecker) this._injector
                    .getInstance(SecurityThresholdChecker.class);
            thresholdChecker.checkSecurityRiskThreshold(repoPath, nonVirtualRepoPaths);
        } catch (CancelException var4) {
            String scoreStr = this._repositories.getProperty(repoPath, PropertiesConstants.RISK_SCORE);
            this._logger.warn(
                    String.format("The download was blocked by security threshold configuration. " +
                                    "Artifact path: %s, CVSS Score: %s",
                            repoPath.getPath(), scoreStr));
            throw var4;
        } catch (Exception var5) {
            this._logger.error(
                    String.format("SCA was unable to complete the security risk threshold verification f" +
                            "or the Artifact: %s.\nException: %s", repoPath.getName(), var5));
        }

    }

    private void checkLicenseAllowance(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        try {
            LicenseAllowanceChecker licenseAllowanceChecker = (LicenseAllowanceChecker) this._injector
                    .getInstance(LicenseAllowanceChecker.class);
            licenseAllowanceChecker.checkLicenseAllowance(repoPath, nonVirtualRepoPaths);
        } catch (CancelException var4) {
            this._logger.warn(String.format("The download was blocked by license allowance configuration. " +
                    "Artifact Name: %s", repoPath.getName()));
            throw var4;
        } catch (Exception var5) {
            this._logger.error(String.format("SCA was unable to complete the license allowance verification " +
                    "for the Artifact: %s.\nException: %s", repoPath.getName(), var5));
        }

    }

    public void scanArtifactsConcurrently(@Nonnull List<RepoPath> repoPaths, boolean forceScan) {
        ArtifactRisksFiller artifactRisksFiller = (ArtifactRisksFiller) this._injector
                .getInstance(ArtifactRisksFiller.class);
        artifactRisksFiller.scanArtifactsConcurrently(repoPaths, forceScan);
    }
}
