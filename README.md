# Jfrog artifactory plugin
This is a reverse engineering project for the sca-artifactory-plugin.jar.

The purpose of this project is to make the lib able to do force scan manually.

## How to use

1. define a user group `cleaners`, add the users, these users will be able to call the REST API
2. update the file `cxsca-security-plugin.groovy`
3. reload the plugin by calling REST API
4. Call the REST API to trigger the SCA scan manually

### new content of file 
See file `cxsca-security-plugin.groovy`
See file `cxsca-security-plugin.properties`

### Disable block

If you want to enable soft block, please change `scaPlugin.beforeDownload(repoPath)`
to `scaPlugin.beforeDownload(repoPath, true)`.

### enable threshold by cvss core

in the property file, add a new line with key `sca.security.risk.threshold.cvss.score` 
and a double value, for example `sca.security.risk.threshold.cvss.score=4.0`

### Block downloading conditions

1. block downloading by CVSS Score or Severity (Property sca.security.risk.threshold or sca.security.risk.threshold.cvss.score)
2. block downloading by Package Blacklist, i.e. package name + version (Property sca.security.packages.blacklist.csv.path)
3. block downloading by Package Blacklist name with CVSS Score / Severity

For condition 1, we can check the properties file, if there is only property for condition 1, will implement condition 1.
For condition 2, we can check the properties file, if there is only property for condition 2, will implement condition 2. If the version is `*`, it will match all version.
For condition 3, we can check the properties file, both property of condition 1 and condition 2 should be in the file. We will only take the package name, ignore its version, and then implement condition 3
