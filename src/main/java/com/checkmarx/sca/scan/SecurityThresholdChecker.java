package com.checkmarx.sca.scan;

import com.checkmarx.sca.PackageManager;
import com.checkmarx.sca.PropertiesConstants;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.configuration.SecurityRiskThreshold;
import com.checkmarx.sca.models.PackageInfo;
import com.google.inject.Inject;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Arrays;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.fs.FileLayoutInfo;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.artifactory.repo.RepositoryConfiguration;
import org.slf4j.Logger;

public class SecurityThresholdChecker {
    @Inject
    private Logger _logger;
    @Inject
    private PluginConfiguration _configuration;
    private final Repositories _repositories;
    private final ArrayList<PackageInfo> _packageBlackList;
    private final ArrayList<PackageInfo> _packageWhiteList;

    public SecurityThresholdChecker(@Nonnull Repositories repositories,
                                    @Nonnull ArrayList<PackageInfo> packageBlackList,
                                    @Nonnull ArrayList<PackageInfo> packageWhiteList) {
        this._repositories = repositories;
        this._packageBlackList = packageBlackList;
        this._packageWhiteList = packageWhiteList;
    }

    public void checkSecurityRiskThreshold(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths)
            throws CancelException {
        String packageNameVersionStr = getPackageTypeNameVersionFromRepoPath(repoPath);
        String[] names = packageNameVersionStr.split(",");
        String packageType = names[0];
        String packageName = names[1];
        String packageVersion = names[2];

        if (inPackagesWhiteList(packageType, packageName, packageVersion)) {
            return;
        }

        if (nonVirtualRepoPaths.size() > 1) {
            this._logger.warn(String.format("More than one RepoPath found for the artifact: %s.", repoPath.getName()));
        }

        Iterator var3 = nonVirtualRepoPaths.iterator();

        String ignoreThreshold;
        do {
            if (!var3.hasNext()) {
                Optional<Double> securityRiskThresholdCvssScore = this._configuration
                        .getSecurityRiskThresholdCvssScore();
                securityRiskThresholdCvssScore.ifPresentOrElse(
                        (value) -> {
                            this.validateSecurityRiskThresholdByCvssScore((RepoPath) nonVirtualRepoPaths.get(0), value);
                        },
                        () -> {
                            this.validateSecurityRiskThresholdFulfillment((RepoPath) nonVirtualRepoPaths.get(0));
                        }
                );
                return;
            }

            RepoPath path = (RepoPath) var3.next();
            ignoreThreshold = this.getIgnoreProperty(path);
        } while (!"true".equalsIgnoreCase(ignoreThreshold));

        this._logger.warn(String.format("Ignoring the security risk threshold. Artifact Property \"%s\" is \"true\". " +
                "Artifact Name: %s", PropertiesConstants.IGNORE_THRESHOLD, repoPath.getName()));
    }

    private String getIgnoreProperty(RepoPath path) {
        String ignoreThreshold = "false";
        Set<Map.Entry<String, String>> properties = this._repositories.getProperties(path).entries();

        for (Map.Entry<String, String> stringStringEntry : properties) {
            Map.Entry<String, String> property = (Map.Entry) stringStringEntry;
            if (PropertiesConstants.IGNORE_THRESHOLD.equalsIgnoreCase((String) property.getKey())) {
                ignoreThreshold = (String) property.getValue();
                break;
            }
        }

        return ignoreThreshold;
    }

    private void validateSecurityRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        SecurityRiskThreshold securityRiskThreshold = this.getSecurityRiskThreshold();
        this._logger.debug(String.format("Security risk threshold configured: %s", securityRiskThreshold));
        switch (securityRiskThreshold) {
            case LOW:
                this.checkIfLowRiskThresholdFulfillment(repoPath);
                break;
            case MEDIUM:
                this.checkIfMediumRiskThresholdFulfillment(repoPath);
                break;
            case HIGH:
                this.checkIfHighRiskThresholdFulfillment(repoPath);
        }

    }

    private SecurityRiskThreshold getSecurityRiskThreshold() {
        String configuration = this._configuration.getPropertyOrDefault(ConfigurationEntry.SECURITY_RISK_THRESHOLD);
        return SecurityRiskThreshold.valueOf(configuration.trim().toUpperCase());
    }

    private void checkIfLowRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {

        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.TOTAL_RISKS_COUNT)) {
            throw new CancelException(String.format("Property CxSCA.TotalRisks missing in %s", repoPath), 403);
        }

        String vulnerabilities = this._repositories.getProperty(repoPath, PropertiesConstants.TOTAL_RISKS_COUNT);
        if (Integer.parseInt(vulnerabilities) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfMediumRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.MEDIUM_RISKS_COUNT)) {
            throw new CancelException(String.format("Property CxSCA.MediumSeverityRisks missing in %s", repoPath), 403);
        }
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.HIGH_RISKS_COUNT)) {
            throw new CancelException(String.format("Property CxSCA.HighSeverityRisks missing in %s", repoPath), 403);
        }
        String mediumRisk = this._repositories.getProperty(repoPath, PropertiesConstants.MEDIUM_RISKS_COUNT);
        String highRisk = this._repositories.getProperty(repoPath, PropertiesConstants.HIGH_RISKS_COUNT);
        if (Integer.parseInt(mediumRisk) > 0 || Integer.parseInt(highRisk) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfHighRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.HIGH_RISKS_COUNT)) {
            throw new CancelException(String.format("Property CxSCA.HighSeverityRisks missing in %s", repoPath), 403);
        }
        String highRisk = this._repositories.getProperty(repoPath, PropertiesConstants.HIGH_RISKS_COUNT);
        if (Integer.parseInt(highRisk) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private String getCancelExceptionMessage(RepoPath repoPath) {
        return String.format("Artifact has risks that do not comply with the security risk threshold. " +
                "Artifact Name: %s", repoPath.getName());
    }

    private void validateSecurityRiskThresholdByCvssScore(RepoPath repoPath, Double scoreConfigured)
            throws CancelException {
        this._logger.debug(String.format("Security risk threshold configured: %s", scoreConfigured));
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.RISK_SCORE)) {
            throw new CancelException(String.format("Property CxSCA.RiskScore missing in %s", repoPath), 403);
        }
        String scoreStr = this._repositories.getProperty(repoPath, PropertiesConstants.RISK_SCORE);
        double score = Double.parseDouble(scoreStr);

        String packageNameVersionStr = getPackageTypeNameVersionFromRepoPath(repoPath);
        String[] names = packageNameVersionStr.split(",");
        String packageType = names[0];
        String packageName = names[1];
        String packageVersion = names[2];

        if (score >= scoreConfigured) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }

        if (scoreBiggerThanOrEqualToBlackListScore(packageType, packageName, packageVersion, score)) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private String getPackageTypeNameVersionFromRepoPath(RepoPath repoPath) {
        String packageWholePath = repoPath.getPath();
        this._logger.debug(String.format("packageWholePath  %s\n", packageWholePath));
        String repositoryKey = repoPath.getRepoKey();
        this._logger.debug(String.format("repository key: %s.", repositoryKey));
        RepositoryConfiguration repoConfiguration = this._repositories.getRepositoryConfiguration(repositoryKey);
        String packageType = repoConfiguration.getPackageType();

        FileLayoutInfo fileLayoutInfo = this._repositories.getLayoutInfo(repoPath);
        
        String packageVersion = fileLayoutInfo.getBaseRevision();
        String packageName = fileLayoutInfo.getModule();
        
        return String.format("%s,%s,%s", packageType,packageName, packageVersion);
    }


    private boolean inPackagesWhiteList(String packageManager, String packageName, String packageVersion) {
        this._logger.debug(String.format("inPackagesWhiteList, packageManager: %s, packageName: %s, packageVersion: %s",
                packageManager, packageName, packageVersion));
        List<PackageInfo> packagesInWhiteList = this._packageWhiteList
                .stream()
                .filter(packageInfo -> packageInfo.getPackageManager().equalsIgnoreCase(packageManager) 
                        && packageInfo.getPackageName().equalsIgnoreCase(packageName)
                        && (packageInfo.getPackageVersion().equalsIgnoreCase("*")
                        || packageInfo.getPackageVersion().equalsIgnoreCase(packageVersion))
                )
                .collect(Collectors.toList());

        return !packagesInWhiteList.isEmpty();
    }

    private boolean scoreBiggerThanOrEqualToBlackListScore(String packageManager, String packageName, String packageVersion, double score) {
        List<PackageInfo> packagesList = this._packageBlackList
                .stream()
                .filter(packageInfo -> packageInfo.getPackageManager().equalsIgnoreCase(packageManager) 
                        && packageInfo.getPackageName().equalsIgnoreCase(packageName)
                        && (packageInfo.getPackageVersion().equalsIgnoreCase("*")
                        || packageInfo.getPackageVersion().equalsIgnoreCase(packageVersion))
                        && (score >= packageInfo.getCvssScore())
                )
                .collect(Collectors.toList());
        boolean violateBlacklist = !packagesList.isEmpty();
        if (violateBlacklist) {
            PackageInfo packageInfo = packagesList.get(0);
            Boolean isMonitored = packageInfo.getMonitored();
            if (isMonitored) {
                this._logger.warn(String.format("This package violate threshold configuration, packagename: %s, " +
                        "packageversion: %s, score: %s", packageName, packageVersion, score));
                return false;
            } else {
                return true;
            }
        }
        return false;
    }

}
