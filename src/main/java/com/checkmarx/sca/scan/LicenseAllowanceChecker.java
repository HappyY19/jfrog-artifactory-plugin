package com.checkmarx.sca.scan;

import com.checkmarx.sca.configuration.ConfigurationEntry;
import com.checkmarx.sca.configuration.PluginConfiguration;
import com.google.inject.Inject;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.annotation.Nonnull;

import org.artifactory.exception.CancelException;
import org.artifactory.repo.RepoPath;
import org.artifactory.repo.Repositories;
import org.slf4j.Logger;

public class LicenseAllowanceChecker {
    @Inject
    private Logger _logger;
    @Inject
    private PluginConfiguration _configuration;
    private final Repositories _repositories;

    public LicenseAllowanceChecker(@Nonnull Repositories repositories) {
        this._repositories = repositories;
    }

    public void checkLicenseAllowance(@Nonnull RepoPath repoPath, @Nonnull ArrayList nonVirtualRepoPaths) throws CancelException {
        if (nonVirtualRepoPaths.size() > 1) {
            this._logger.warn(String.format("More than one RepoPath found for the artifact: %s.", repoPath.getName()));
        }

        Iterator var3 = nonVirtualRepoPaths.iterator();

        String ignoreThreshold;
        do {
            if (!var3.hasNext()) {
                this.validateLicenseAllowanceFulfillment((RepoPath) nonVirtualRepoPaths.get(0));
                return;
            }

            RepoPath path = (RepoPath) var3.next();
            ignoreThreshold = this.getIgnoreProperty(path);
        } while (!"true".equalsIgnoreCase(ignoreThreshold));

        this._logger.warn(String.format("Ignoring the License allowance. Artifact Property \"%s\" is \"true\". Artifact Name: %s", "CxSCA.IgnoreLicenses", repoPath.getName()));
    }

    private String getIgnoreProperty(RepoPath path) {
        String ignoreLicense = "false";
        Set properties = this._repositories.getProperties(path).entries();
        Iterator var4 = properties.iterator();

        while (var4.hasNext()) {
            Map.Entry property = (Map.Entry) var4.next();
            if ("CxSCA.IgnoreLicenses".equalsIgnoreCase((String) property.getKey())) {
                ignoreLicense = (String) property.getValue();
                break;
            }
        }

        return ignoreLicense;
    }

    private void validateLicenseAllowanceFulfillment(RepoPath repoPath) throws CancelException {
        Set licenseAllowanceList = this.getLicenseAllowanceList();
        this._logger.debug(String.format("License allowance configured: [%s]", String.join(", ", licenseAllowanceList)));
        if (licenseAllowanceList.size() != 0) {
            if (licenseAllowanceList.size() == 1 && licenseAllowanceList.toArray()[0].toString().equalsIgnoreCase("none")) {
                throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
            } else {
                List licenses = List.of(this._repositories.getProperty(repoPath, "CxSCA.Licenses").split(","));
                Stream var10000 = licenseAllowanceList.stream();
                Objects.requireNonNull(licenses);
                if (var10000.noneMatch(licenses::contains)) {
                    throw new CancelException(this.getCancelExceptionMessage(repoPath), 403);
                }
            }
        }
    }

    private Set getLicenseAllowanceList() {
        String allowance = this._configuration.getPropertyOrDefault(ConfigurationEntry.LICENSES_ALLOWED);
        if (allowance != null) {
            try {
                String[] licenses = allowance.split(",");
                return (Set) Arrays.stream(licenses).filter((name) -> {
                    return !name.isBlank();
                }).map(String::trim).collect(Collectors.toSet());
            } catch (Exception var3) {
                this._logger.warn(String.format("License allowance not configured: %s", allowance));
                throw var3;
            }
        } else {
            return new HashSet();
        }
    }

    private String getCancelExceptionMessage(RepoPath repoPath) {
        return String.format("License allowance not compliant for the artifact: %s", repoPath.getName());
    }
}
