package com.checkmarx.sca.scan;

import com.checkmarx.sca.PropertiesConstants;
import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.configuration.SecurityRiskThreshold;
import com.checkmarx.sca.models.PackageInfo;
import com.google.inject.Inject;

import java.util.*;
import java.util.stream.Collectors;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
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
        String packageNameVersionStr = getPackageNameVersionFromRepoPath(repoPath);
        String[] names = packageNameVersionStr.split(",");
        String packageName = names[0];
        String packageVersion = names[1];

        if (inPackagesWhiteList(packageName, packageVersion)) {
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
                    ()-> {
                        this.validateSecurityRiskThresholdFulfillment((RepoPath) nonVirtualRepoPaths.get(0));
                    }
                );
                return;
            }

            RepoPath path = (RepoPath) var3.next();
            ignoreThreshold = this.getIgnoreProperty(path);
        } while (!"true".equalsIgnoreCase(ignoreThreshold));

        this._logger.warn(String.format("Ignoring the security risk threshold. Artifact Property \"%s\" is \"true\". " +
                "Artifact Name: %s", PropertiesConstants.IGNORE_RISK_THRESHOLD, repoPath.getName()));
    }

    private String getIgnoreProperty(RepoPath path) {
        String ignoreThreshold = "false";
        Set<Map.Entry<String, String>> properties = this._repositories.getProperties(path).entries();

        for (Map.Entry<String, String> stringStringEntry : properties) {
            Map.Entry<String, String> property = (Map.Entry) stringStringEntry;
            if (PropertiesConstants.IGNORE_RISK_THRESHOLD.equalsIgnoreCase((String) property.getKey())) {
                ignoreThreshold = (String) property.getValue();
                break;
            }
        }

        return ignoreThreshold;
    }

    private void validateSecurityRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        SecurityRiskThreshold securityRiskThreshold = this._configuration.getSecurityRiskThreshold();
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

    private void checkIfLowRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {

        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.TOTAL_RISKS)) {
            throw new CancelException(String.format("Property CxSCA.TotalRisks missing in %s", repoPath), 403);
        }

        String vulnerabilities = this._repositories.getProperty(repoPath, PropertiesConstants.TOTAL_RISKS);
        if (Integer.parseInt(vulnerabilities) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfMediumRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.MEDIUM_SEVERITY_RISKS)) {
            throw new CancelException(String.format("Property CxSCA.MediumSeverityRisks missing in %s", repoPath), 403);
        }
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.HIGH_SEVERITY_RISKS)) {
            throw new CancelException(String.format("Property CxSCA.HighSeverityRisks missing in %s", repoPath), 403);
        }
        String mediumRisk = this._repositories.getProperty(repoPath, PropertiesConstants.MEDIUM_SEVERITY_RISKS);
        String highRisk = this._repositories.getProperty(repoPath, PropertiesConstants.HIGH_SEVERITY_RISKS);
        if (Integer.parseInt(mediumRisk) > 0 || Integer.parseInt(highRisk) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfHighRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        if (!this._repositories.hasProperty(repoPath, PropertiesConstants.HIGH_SEVERITY_RISKS)) {
            throw new CancelException(String.format("Property CxSCA.HighSeverityRisks missing in %s", repoPath), 403);
        }
        String highRisk = this._repositories.getProperty(repoPath, PropertiesConstants.HIGH_SEVERITY_RISKS);
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

        String packageNameVersionStr = getPackageNameVersionFromRepoPath(repoPath);
        String[] names = packageNameVersionStr.split(",");
        String packageName = names[0];
        String packageVersion = names[1];

        if (this._packageBlackList.isEmpty()) {
            if (score >= scoreConfigured) {
                throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
            }
        } else {
            if (score >= scoreConfigured || scoreBiggerThanOrEqualToBlackListScore(packageName, packageVersion, score)) {
                throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
            }
        }
    }

    private String getPackageNameVersionFromRepoPath(RepoPath repoPath) {
        String packageWholePath = repoPath.getPath();
        this._logger.debug(String.format("packageWholePath  %s\n", packageWholePath));
        String[] names = packageWholePath.split("/");
        String fileName = names[names.length - 1];
        String[] packageNameVersionStr = fileName.split("-");
        String[] newPackageNameVersionStr =  Arrays.copyOfRange(packageNameVersionStr, 0, packageNameVersionStr.length - 1);
        String packageName = String.join("-", newPackageNameVersionStr);
        String packageVersionWithFileExtension = packageNameVersionStr[packageNameVersionStr.length - 1];
        String[] packageVersionWithFileExtensionStr = packageVersionWithFileExtension.split("\\.");
        String[] packageVersionStr = Arrays.copyOfRange(packageVersionWithFileExtensionStr, 0, packageVersionWithFileExtensionStr.length - 1);
        String packageVersion = String.join(".", packageVersionStr);
        return String.format("%s,%s", packageName, packageVersion) ;
    }


    private boolean inPackagesWhiteList(String packageName, String packageVersion){
        this._logger.debug(String.format("inPackagesWhiteList, packageName: %s, packageVersion: %s", packageName, packageVersion));
        List<PackageInfo> packagesInWhiteList = this._packageWhiteList
                .stream()
                .filter(packageInfo -> packageInfo.getPackageName().equalsIgnoreCase(packageName)
                        && (packageInfo.getPackageVersion().equalsIgnoreCase("*")
                                || packageInfo.getPackageVersion().equalsIgnoreCase(packageVersion))
                )
                .collect(Collectors.toList());

        return !packagesInWhiteList.isEmpty();
    }

    private boolean scoreBiggerThanOrEqualToBlackListScore(String packageName, String packageVersion, double score) {
        List<PackageInfo> packagesList = this._packageBlackList
                .stream()
                .filter(packageInfo -> packageInfo.getPackageName().equalsIgnoreCase(packageName)
                        && (packageInfo.getPackageVersion().equalsIgnoreCase("*")
                        || packageInfo.getPackageVersion().equalsIgnoreCase(packageVersion))
                        && (score >= packageInfo.getCvssScore())
                )
                .collect(Collectors.toList());
        return !packagesList.isEmpty();
    }

}
