package com.checkmarx.sca.configuration;

import com.checkmarx.sca.communication.models.AccessControlCredentials;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import java.util.Optional;

import org.slf4j.Logger;

public class PluginConfiguration {
    private final Logger logger;
    private final Properties properties;
    private boolean hasAuthConfiguration = false;

    public PluginConfiguration(@Nonnull Properties properties, @Nonnull Logger logger) {
        this.properties = properties;
        this.logger = logger;
    }

    public Set<Map.Entry<Object, Object>> getPropertyEntries() {
        return new HashSet(this.properties.entrySet());
    }

    public String getProperty(IConfigurationEntry config) {
        return this.properties.getProperty(config.propertyKey());
    }

    public String getPropertyOrDefault(IConfigurationEntry config) {
        return this.properties.getProperty(config.propertyKey(), config.defaultValue());
    }

    public boolean hasAuthConfiguration() {
        return this.hasAuthConfiguration;
    }

    public AccessControlCredentials getAccessControlCredentials() {
        try {
            String account = this.getPropertyOrDefault(ConfigurationEntry.ACCOUNT);
            String username = this.getPropertyOrDefault(ConfigurationEntry.USERNAME);
            String password = this.getPropertyOrDefault(ConfigurationEntry.PASSWORD);
            String envValue = System.getenv(password);
            if (envValue != null) {
                password = envValue;
            }

            return new AccessControlCredentials(username, password, account);
        } catch (Exception var5) {
            this.logger.error("Failed to get access control credentials.");
            this.logger.error(var5.getMessage(), var5);
            throw var5;
        }
    }

    public void validate() {
        this.validateAuthConfig();
        this.validateExpirationConfig();
        this.validateSeverityThresholdConfig();
        this.validateSeverityThresholdCvssScoreConfig();
        this.validateLicensesAllowedConfig();
    }

    private void validateExpirationConfig() {
        String expirationTime = this.getProperty(ConfigurationEntry.DATA_EXPIRATION_TIME);
        if (expirationTime != null) {
            try {
                int definedValue = Integer.parseInt(expirationTime);
                int minimumExpirationTime = 1800;
                if (definedValue < minimumExpirationTime) {
                    this.properties.setProperty(ConfigurationEntry.DATA_EXPIRATION_TIME.propertyKey(),
                            String.valueOf(minimumExpirationTime));
                    this.logger.warn("The configuration value defined for the property 'sca.data.expiration-time' " +
                            "is lower than the minimum value allowed. The minimum value will be used.");
                }
            } catch (Exception var4) {
                this.logger.warn(String.format("Error converting the 'sca.data.expiration-time' configuration value," +
                        " the default value will be used. Exception Message: %s.", var4.getMessage()));
                this.properties.setProperty(ConfigurationEntry.DATA_EXPIRATION_TIME.propertyKey(),
                        ConfigurationEntry.DATA_EXPIRATION_TIME.defaultValue());
            }
        }

    }

    private void validateSeverityThresholdConfig() {
        String threshold = this.getProperty(ConfigurationEntry.SECURITY_RISK_THRESHOLD);
        if (threshold != null) {
            try {
                SecurityRiskThreshold.valueOf(threshold.trim().toUpperCase());
            } catch (Exception var3) {
                this.logger.error(String.format("Error converting the 'sca.security.risk.threshold' configuration " +
                        "value, we will use the default value (LOW). Exception Message: %s.", var3.getMessage()));
                throw var3;
            }
        }

    }

    private void validateSeverityThresholdCvssScoreConfig() {
        String cvssScore = this.getPropertyOrDefault(ConfigurationEntry.SECURITY_RISK_THRESHOLD_CVSS_SCORE);
        if (cvssScore != null) {
            try {
                Float.parseFloat(cvssScore);
            } catch (Exception var3) {
                this.logger.error("cvss score %s cannot be converted to float: " + var3.getMessage()
                                + ", will use the default value 0.0",
                        cvssScore);
                throw var3;
            }
        }
    }

    private void validateLicensesAllowedConfig() {
        String allowance = this.getProperty(ConfigurationEntry.LICENSES_ALLOWED);
        if (allowance != null) {
            try {
                String[] licenses = allowance.split(",");
                Stream var3 = Arrays.stream(licenses).filter((license) -> {
                    return !license.isEmpty();
                }).distinct();
            } catch (Exception var4) {
                this.logger.error(String.format("Error converting '%s' configuration value, no license restrictions " +
                                "applied. Exception Message: %s.", ConfigurationEntry.LICENSES_ALLOWED.propertyKey(),
                        var4.getMessage()));
                throw var4;
            }
        }

    }

    private void validateAuthConfig() {
        String account = this.getPropertyOrDefault(ConfigurationEntry.ACCOUNT);
        String username = this.getPropertyOrDefault(ConfigurationEntry.USERNAME);
        String password = this.getPropertyOrDefault(ConfigurationEntry.PASSWORD);
        if (!Objects.equals(account, (Object) null)
                || !Objects.equals(username, (Object) null)
                || !Objects.equals(password, (Object) null)) {
            ArrayList<String> missingFields = new ArrayList();
            if (Objects.equals(account, (Object) null)) {
                missingFields.add(ConfigurationEntry.ACCOUNT.propertyKey());
            }

            if (Objects.equals(username, (Object) null)) {
                missingFields.add(ConfigurationEntry.USERNAME.propertyKey());
            }

            if (Objects.equals(password, (Object) null)) {
                missingFields.add(ConfigurationEntry.PASSWORD.propertyKey());
            }

            if (missingFields.isEmpty()) {
                this.hasAuthConfiguration = true;
            } else {
                String message = String.format("A mandatory authentication configuration is missing. " +
                        "(Missing configurations: %s)", String.join(", ", missingFields));
                this.logger.error(message);
                this.logger.info("Working without authentication.");
            }
        }
    }

    public SecurityRiskThreshold getSecurityRiskThreshold() {
        String configuration = this.getPropertyOrDefault(ConfigurationEntry.SECURITY_RISK_THRESHOLD);
        return SecurityRiskThreshold.valueOf(configuration.trim().toUpperCase());
    }

    public Optional<Double> getSecurityRiskThresholdCvssScore() {
        Optional<Double> value = Optional.empty();
        String cvssScore = this.getPropertyOrDefault(ConfigurationEntry.SECURITY_RISK_THRESHOLD_CVSS_SCORE);
        if (cvssScore != null) {
            try {
                value = Optional.of(Double.parseDouble(cvssScore));
            } catch (Exception var3) {
                this.logger.error("cvss score %s cannot be converted to float: " + var3.getMessage()
                                + ", will use the default value 0.0",
                        cvssScore);
            }
        }
        return value;
    }

    public String getScaSecurityBlockRepositoryKeys() {
        return this.getPropertyOrDefault(ConfigurationEntry.BLOCK_REPOSITORY_KEYS);
    }

    public Logger getLogger() {
        return this.logger;
    }

}
