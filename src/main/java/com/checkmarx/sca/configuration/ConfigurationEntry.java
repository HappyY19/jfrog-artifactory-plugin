package com.checkmarx.sca.configuration;

public enum ConfigurationEntry implements IConfigurationEntry {
    API_URL("sca.api.url", "https://api-sca.checkmarx.net"),
    AUTHENTICATION_URL("sca.authentication.url", "https://platform.checkmarx.net/"),
    DATA_EXPIRATION_TIME("sca.data.expiration-time", "21600"),
    SECURITY_RISK_THRESHOLD("sca.security.risk.threshold", "None"),
    SECURITY_RISK_THRESHOLD_CVSS_SCORE("sca.security.risk.threshold.cvss.score", (String) null),
    LICENSES_ALLOWED("sca.licenses.allowed", ""),
    PACKAGIST_REPOSITORY("packagist.repository", "https://packagist.org"),
    ACCOUNT("sca.account", (String) null),
    USERNAME("sca.username", (String) null),
    PASSWORD("sca.password", (String) null);

    private final String propertyKey;
    private final String defaultValue;

    private ConfigurationEntry(String propertyKey, String defaultValue) {
        this.propertyKey = propertyKey;
        this.defaultValue = defaultValue;
    }

    public String propertyKey() {
        return this.propertyKey;
    }

    public String defaultValue() {
        return this.defaultValue;
    }
}
