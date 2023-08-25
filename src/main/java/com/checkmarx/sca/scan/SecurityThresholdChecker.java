package com.checkmarx.sca.scan;

import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.checkmarx.sca.configuration.SecurityRiskThreshold;
import com.google.inject.Inject;

import java.util.*;
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

    public SecurityThresholdChecker(@Nonnull Repositories repositories) {
        this._repositories = repositories;
    }

    public void checkSecurityRiskThreshold(@Nonnull RepoPath repoPath, @Nonnull ArrayList<RepoPath> nonVirtualRepoPaths)
            throws CancelException {
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
                "Artifact Name: %s", "CxSCA.IgnoreRiskThreshold", repoPath.getName()));
    }

    private String getIgnoreProperty(RepoPath path) {
        String ignoreThreshold = "false";
        Set<Map.Entry<String, String>> properties = this._repositories.getProperties(path).entries();

        for (Map.Entry<String, String> stringStringEntry : properties) {
            Map.Entry<String, String> property = (Map.Entry) stringStringEntry;
            if ("CxSCA.IgnoreRiskThreshold".equalsIgnoreCase((String) property.getKey())) {
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
        String vulnerabilities = this._repositories.getProperty(repoPath, "CxSCA.TotalRisks");
        if (Integer.parseInt(vulnerabilities) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfMediumRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        String mediumRisk = this._repositories.getProperty(repoPath, "CxSCA.MediumSeverityRisks");
        String highRisk = this._repositories.getProperty(repoPath, "CxSCA.HighSeverityRisks");
        if (Integer.parseInt(mediumRisk) > 0 || Integer.parseInt(highRisk) > 0) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }

    private void checkIfHighRiskThresholdFulfillment(RepoPath repoPath) throws CancelException {
        String highRisk = this._repositories.getProperty(repoPath, "CxSCA.HighSeverityRisks");
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
        String score = this._repositories.getProperty(repoPath, "CxSCA.RiskScore");
        if (Double.parseDouble(score) > scoreConfigured) {
            throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
        }
    }
}
