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

### soft block

If you want to enable soft block, please change `scaPlugin.beforeDownload(repoPath)`
to `scaPlugin.beforeDownload(repoPath, true)`.

### enable threshold by cvss core

in the property file, add a new line with key `sca.security.risk.threshold.cvss.score` 
and a double value, for example `sca.security.risk.threshold.cvss.score=4.0`
