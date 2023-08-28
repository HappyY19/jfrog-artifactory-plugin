# Jfrog artifactory plugin
This is a reverse engineering project for the sca-artifactory-plugin.jar.

The purpose of this project is to make the lib able to do force scan manually.

## How to use

1. define a user group `cleaners`, add the users, these users will be able to call the REST API
2. update the file `cxsca-security-plugin.groovy`
3. reload the plugin by calling REST API
4. Call the REST API to trigger the SCA scan manually

### new content of file `cxsca-security-plugin.groovy`

```groovy
ackage com.checkmarx.sca

import groovy.transform.Field
import org.artifactory.repo.RepoPath
import org.artifactory.request.Request

@Field ScaPlugin scaPlugin

scanExistingArtifacts()

private void scanExistingArtifacts() {
    log.info("Initializing Security Plugin...")

    File pluginsDirectory = ctx.artifactoryHome.pluginsDir
    scaPlugin = new ScaPlugin(log, pluginsDirectory, repositories)

    searches.artifactsByName('*').each { artifact ->
        scaPlugin.checkArtifactsAlreadyPresent(artifact)
        scaPlugin.checkArtifactsForSuggestionOnPrivatePackages(artifact)
    }

    log.info("Initialization of Sca Security Plugin completed")
}

download {
    beforeDownload { Request request, RepoPath repoPath ->
        scaPlugin.beforeDownload(repoPath)
    }
}

upload {
    beforeUploadRequest { Request request, RepoPath repoPath ->
        scaPlugin.beforeUpload(repoPath)
    }
}

// curl -i -uadmin:password -X POST "http://localhost:8082/artifactory/api/plugins/execute/scaScanCtl?params=command=start"
def pluginGroup = 'cleaners'
executions {
    scaScanCtl(groups: [pluginGroup]) { params ->
        def command = params['command'] ? params['command'][0] as String : ''

        switch ( command ) {
            case "start":
                log.info("Execute Sca Scan Start")
                searches.artifactsByName('*').each { artifact ->
                    scaPlugin.checkArtifactsAlreadyPresent(artifact, true)
                }
                log.info("Execute Sca Scan Completed")
                break

            default:
                log.info("Missing or invalid command, '$command'")
        }
    }
}

```

### soft block

If you want to enable soft block, please change `scaPlugin.beforeDownload(repoPath)`
to `scaPlugin.beforeDownload(repoPath, true)`.

### enable threshold by cvss core

in the property file, add a new line with key `sca.security.risk.threshold.cvss.score` 
and a double value, for example `sca.security.risk.threshold.cvss.score=4.0`
