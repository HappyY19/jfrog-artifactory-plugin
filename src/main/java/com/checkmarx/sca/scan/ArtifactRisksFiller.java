package com.checkmarx.sca.scan;

import com.checkmarx.sca.IPackageManager;
import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.communication.ScaHttpClient;
import com.checkmarx.sca.communication.exceptions.UnexpectedResponseCodeException;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.configuration.SecurityRiskThreshold;
import com.checkmarx.sca.models.ArtifactId;
import com.checkmarx.sca.models.ArtifactInfo;
import com.checkmarx.sca.models.PackageAnalysisAggregation;
import com.checkmarx.sca.models.VulnerabilitiesAggregation;
import com.google.inject.Inject;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import javax.annotation.Nonnull;

import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.md.Properties;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;

public class ArtifactRisksFiller {
    @Inject
    private Logger _logger;
    @Inject
    private ScaHttpClient _scaHttpClient;
    @Inject
    private ArtifactIdBuilder _artifactIdBuilder;
    @Inject
    private PluginConfiguration _configuration;
    private final Repositories _repositories;

    public ArtifactRisksFiller(@Nonnull Repositories repositories) {
        this._repositories = repositories;
    }

    public boolean addArtifactRisks(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths,
                                    boolean forceScan) {
        String repositoryKey = repoPath.getRepoKey();
        RepositoryConfiguration repoConfiguration = this._repositories.getRepositoryConfiguration(repositoryKey);
        if (nonVirtualRepoPaths.isEmpty()) {
            this._logger.warn(String.format("Artifact not found in any repository. Artifact name: %s.",
                    repoPath.getName()));
            return false;
        } else if (!forceScan && this.scanIsNotNeeded(nonVirtualRepoPaths)) {
            this._logger.info(String.format("Scan ignored by cache configuration. Artifact name: %s",
                    repoPath.getName()));
            this.logThresholdViolationArtifact(repoPath, nonVirtualRepoPaths);
            return true;
        } else {
            ArtifactId artifactId;
            try {
                String packageType = repoConfiguration.getPackageType();
                PackageManager packageManager = PackageManager.GetPackageType(packageType);
                if (this.FileShouldBeIgnored(repoPath, packageManager)) {
                    this._logger.debug(String.format("Not an artifact should be ignored. File Name: %s",
                            repoPath.getName()));
                    return false;
                }

                FileLayoutInfo fileLayoutInfo = this._repositories.getLayoutInfo(repoPath);
                artifactId = this._artifactIdBuilder.getArtifactId(fileLayoutInfo, repoPath, packageManager);
                if (artifactId.isInvalid()) {
                    this._logger.error(String.format("The artifact id was not built correctly. " +
                            "PackageType: %s, Name: %s, Version: %s", artifactId.PackageType, artifactId.Name,
                            artifactId.Version));
                    return false;
                }
            } catch (Exception var9) {
                this._logger.error(String.format("Exception Message: %s. Artifact Name: %s.", var9.getMessage(),
                        repoPath.getName()), var9);
                return false;
            }

            this._logger.info(String.format("Started artifact verification. Artifact name: %s", repoPath.getPath()));
            PackageAnalysisAggregation packageRiskAggregation = this.scanArtifact(artifactId);
            boolean risksAddedSuccessfully = false;
            if (packageRiskAggregation != null) {
                this.addArtifactAnalysisInfo(nonVirtualRepoPaths, packageRiskAggregation);
                this.logThresholdViolationArtifact(repoPath, nonVirtualRepoPaths);
                risksAddedSuccessfully = true;
            }
            this._logger.info(String.format("Ended the artifact verification. Artifact name: %s", repoPath.getPath()));
            return risksAddedSuccessfully;
        }
    }

    private void logThresholdViolationArtifact(
            @Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths) {
        String repositoryKey = repoPath.getRepoKey();
        RepositoryConfiguration repoConfiguration = this._repositories.getRepositoryConfiguration(repositoryKey);
        String packageType = repoConfiguration.getPackageType();
        PackageManager packageManager = PackageManager.GetPackageType(packageType);
        FileLayoutInfo fileLayoutInfo = this._repositories.getLayoutInfo(repoPath);
        ArtifactId artifactId = this._artifactIdBuilder.getArtifactId(fileLayoutInfo, repoPath, packageManager);
        Optional<Double> securityRiskThresholdCvssScore = this._configuration.getSecurityRiskThresholdCvssScore();
        securityRiskThresholdCvssScore.ifPresentOrElse(
                (value) -> {
                    this.logThresholdViolationByCvssScore((RepoPath) nonVirtualRepoPaths.get(0), artifactId, value);
                },
                ()-> {
                    this.logThresholdViolationBySeverity((RepoPath) nonVirtualRepoPaths.get(0), artifactId);
                }
        );
    }

    private void logThresholdViolationBySeverity(RepoPath repoPath,
                                                 ArtifactId artifactId) {

        String vulnerabilities = this._repositories.getProperty(repoPath, "CxSCA.TotalRisks");
        String mediumRisk = this._repositories.getProperty(repoPath, "CxSCA.MediumSeverityRisks");
        String highRisk = this._repositories.getProperty(repoPath, "CxSCA.HighSeverityRisks");
        SecurityRiskThreshold securityRiskThreshold = this._configuration.getSecurityRiskThreshold();
        this._logger.debug(String.format("Security risk threshold configured: %s", securityRiskThreshold));
        switch (securityRiskThreshold) {
            case LOW:
                if (Integer.parseInt(vulnerabilities) > 0) {
                    this._logger.info(
                            String.format("Artifact vulnerabilities violate the security risk threshold LOW " +
                                            "PackageType: %s, Name: %s, Version: %s", artifactId.PackageType,
                                    artifactId.Name,
                                    artifactId.Version)
                    );
                }
                break;
            case MEDIUM:
                if (Integer.parseInt(mediumRisk) > 0 || Integer.parseInt(highRisk) > 0) {
                    this._logger.info(
                            String.format("Artifact vulnerabilities violate the security risk threshold MEDIUM " +
                                            "PackageType: %s, Name: %s, Version: %s", artifactId.PackageType,
                                    artifactId.Name,
                                    artifactId.Version)
                    );
                }
                break;
            case HIGH:
                if (Integer.parseInt(highRisk) > 0) {
                    this._logger.info(
                            String.format("Artifact vulnerabilities violate the security risk threshold HIGH " +
                                            "PackageType: %s, Name: %s, Version: %s", artifactId.PackageType,
                                    artifactId.Name,
                                    artifactId.Version)
                    );
                }
        }
    }

    private void logThresholdViolationByCvssScore(RepoPath repoPath,
                                                  ArtifactId artifactId, Double configScore) {

        String score = this._repositories.getProperty(repoPath, "CxSCA.RiskScore");
        Double cvssScore = Double.valueOf(score);

        if (cvssScore > configScore) {
            this._logger.info(
                    String.format("Artifact vulnerabilities violate the security risk threshold cvss core: %f  " +
                                    "PackageType: %s, Name: %s, Version: %s", configScore, artifactId.PackageType,
                            artifactId.Name,
                            artifactId.Version)
            );
        }

    }

    private boolean scanIsNotNeeded(@Nonnull ArrayList<RepoPath> repoPaths) {
        int expirationTime = this.getExpirationTime();
        Iterator<RepoPath> var3 = repoPaths.iterator();

        RepoPath repoPath;
        do {
            if (!var3.hasNext()) {
                return true;
            }

            repoPath = (RepoPath) var3.next();
        } while (this.scanIsNotNeeded(repoPath, expirationTime));

        return false;
    }

    private boolean scanIsNotNeeded(@Nonnull RepoPath repoPath, int expirationTime) {
        try {
            if (!this._repositories.exists(repoPath)) {
                return false;
            } else {
                Properties properties = this._repositories.getProperties(repoPath);
                if (properties != null && this.allPropertiesDefined(properties)) {
                    String scanDate = properties.getFirst("CxSCA.LastScanned");
                    if (scanDate != null && !scanDate.trim().isEmpty()) {
                        Instant instantDate = Instant.parse(scanDate);
                        instantDate = instantDate.plusSeconds((long) expirationTime);
                        return Instant.now().compareTo(instantDate) < 0;
                    } else {
                        return false;
                    }
                } else {
                    this._logger.debug(String.format("There are missing properties, the scan will be performed. " +
                            "Artifact: %s", repoPath.getName()));
                    return false;
                }
            }
        } catch (Exception var6) {
            this._logger.error(String.format("Unexpected error when checking the last scan date for " +
                    "the artifact: %s", repoPath.getName()), var6);
            return false;
        }
    }

    private boolean allPropertiesDefined(Properties properties) {
        return properties.containsKey("CxSCA.TotalRisks")
                && properties.containsKey("CxSCA.LowSeverityRisks")
                && properties.containsKey("CxSCA.MediumSeverityRisks")
                && properties.containsKey("CxSCA.HighSeverityRisks")
                && properties.containsKey("CxSCA.RiskScore")
                && properties.containsKey("CxSCA.RiskLevel")
                && properties.containsKey("CxSCA.LastScanned");
    }

    private int getExpirationTime() {
        String configurationTime = this._configuration.getPropertyOrDefault(ConfigurationEntry.DATA_EXPIRATION_TIME);

        try {
            return Integer.parseInt(configurationTime);
        } catch (Exception var3) {
            this._logger.warn(String.format("Error converting the 'sca.data.expiration-time' configuration value, " +
                    "we will use the default value. Exception Message: %s.", var3.getMessage()));
            return Integer.parseInt(ConfigurationEntry.DATA_EXPIRATION_TIME.defaultValue());
        }
    }

    private boolean FileShouldBeIgnored(RepoPath repoPath, IPackageManager packageManager) {
        boolean notNugetPackage = packageManager == PackageManager.NUGET && !repoPath.getPath().endsWith(".nupkg");
        boolean notGoPackage = packageManager == PackageManager.GO && !repoPath.getPath().endsWith(".zip");
        boolean notCocoaPodsPackage = packageManager == PackageManager.COCOAPODS
                && !repoPath.getPath().endsWith(".tar.gz")
                && !repoPath.getPath().endsWith(".zip");
        boolean jsonFile = repoPath.getPath().endsWith(".json");
        boolean htmlFile = repoPath.getPath().endsWith(".html");
        return notNugetPackage || notGoPackage || notCocoaPodsPackage || jsonFile || htmlFile;
    }

    private PackageAnalysisAggregation scanArtifact(@Nonnull ArtifactId artifactId) {
        ArtifactInfo artifactInfo;
        try {
            artifactInfo = this._scaHttpClient.getArtifactInformation(artifactId.PackageType, artifactId.Name,
                    artifactId.Version);
            this._logger.debug(String.format("For CxSCA the artifact is identified by %s.", artifactInfo.getId()));
        } catch (Exception var5) {
            if (var5 instanceof UnexpectedResponseCodeException
                    && ((UnexpectedResponseCodeException) var5).StatusCode == 404) {
                this._logger.error(String.format("Artifact not found, artifact name: %s. Exception Message: %s.",
                        artifactId.Name, var5.getMessage()));
                return null;
            }

            this._logger.error(String.format("Failed to get artifact information. " +
                    "Exception Message: %s. Artifact Name: %s.", var5.getMessage(), artifactId.Name));
            return null;
        }

        try {
            return this._scaHttpClient.getRiskAggregationOfArtifact(artifactInfo.getPackageType(),
                    artifactInfo.getName(), artifactInfo.getVersion());
        } catch (Exception var4) {
            this._logger.error(String.format("Failed to get risk aggregation of artifact. " +
                    "Exception Message: %s. Artifact Name: %s.", var4.getMessage(), artifactId.Name));
            return null;
        }
    }

    private void addArtifactAnalysisInfo(@Nonnull ArrayList<RepoPath> repoPaths,
                                         @Nonnull PackageAnalysisAggregation packageAnalysisAggregation) {

        for (RepoPath repoPath : repoPaths) {
            try {
                this.addArtifactAnalysisInfo(repoPath, packageAnalysisAggregation);
            } catch (Exception var6) {
                this._logger.error(String.format("Failed to add risks information to the properties. " +
                        "Exception Message: %s. Artifact Name: %s.", var6.getMessage(), repoPath.getName()));
            }
        }

    }

    private void addArtifactAnalysisInfo(RepoPath repoPath, PackageAnalysisAggregation packageAnalysisAggregation) {
        VulnerabilitiesAggregation vulnerabilitiesAggregation = packageAnalysisAggregation
                .getVulnerabilitiesAggregation();
        List<String> licenceTypes = packageAnalysisAggregation.getLicenses();
        if (licenceTypes == null) {
            licenceTypes = List.of();
        }

        this._repositories.setProperty(repoPath, "CxSCA.TotalRisks",
                new String[]{String.valueOf(vulnerabilitiesAggregation.getVulnerabilitiesCount())});
        this._repositories.setProperty(repoPath, "CxSCA.LowSeverityRisks",
                new String[]{String.valueOf(vulnerabilitiesAggregation.getLowRiskCount())});
        this._repositories.setProperty(repoPath, "CxSCA.MediumSeverityRisks",
                new String[]{String.valueOf(vulnerabilitiesAggregation.getMediumRiskCount())});
        this._repositories.setProperty(repoPath, "CxSCA.HighSeverityRisks",
                new String[]{String.valueOf(vulnerabilitiesAggregation.getHighRiskCount())});
        this._repositories.setProperty(repoPath, "CxSCA.RiskScore",
                new String[]{String.valueOf(vulnerabilitiesAggregation.getMaxRiskScore())});
        this._repositories.setProperty(repoPath, "CxSCA.RiskLevel",
                new String[]{vulnerabilitiesAggregation.getMaxRiskSeverity()});
        this._repositories.setProperty(repoPath, "CxSCA.LastScanned",
                new String[]{Instant.now().toString()});
        this._repositories.setProperty(repoPath, "CxSCA.Licenses",
                new String[]{String.join(",", licenceTypes)});
    }
}
