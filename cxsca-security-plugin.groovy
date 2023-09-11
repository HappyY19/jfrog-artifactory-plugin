package com.checkmarx.sca

import groovy.transform.Field
import org.artifactory.repo.RepoPath
import org.artifactory.request.Request


@Field ScaPlugin scaPlugin


scanExistingArtifacts()

private void scanExistingArtifacts() {
    log.info("Initializing Security Plugin...")

    File pluginsDirectory = ctx.artifactoryHome.pluginsDir
    scaPlugin = new ScaPlugin(log, pluginsDirectory, repositories)

//    The following code is comment out because scanning everything for a large Jfrog instance takes very long time
//    searches.artifactsByName('*').each { artifact ->
//        scaPlugin.checkArtifactsAlreadyPresent(artifact)
//        scaPlugin.checkArtifactsForSuggestionOnPrivatePackages(artifact)
//    }

    log.info("Initialization of Sca Security Plugin completed")
}

download {
    beforeDownload { Request request, RepoPath repoPath ->
        log.info "before download process started"
        scaPlugin.beforeDownload(repoPath)
        log.info "before download process completed"
    }
}

upload {
    beforeUploadRequest { Request request, RepoPath repoPath ->
        log.info "before upload process started"
        scaPlugin.beforeUpload(repoPath)
        log.info "before upload process completed"
    }
}

// curl -i -u admin:password -X POST "http://localhost:8082/artifactory/api/plugins/execute/scaScanCtl?params=searchPattern=*.whl;repos=pypi-remote-cache;forceScan=true"

def pluginGroup = 'cleaners'
executions {
    scaScanCtl(groups: [pluginGroup]) { params ->
        def searchPattern = params['searchPattern'] ? params['searchPattern'][0] as String : ''
        log.info "searchPattern:  $searchPattern"
        // Ensure the given repo list is not empty
        def repos = params?.get('repos')
        if (!repos) {
            log.debug("No repos were given to index.")
            status = 400
            return
        }

        log.info "repos:  $repos"

        def forceScan = params['forceScan'] ? params['forceScan'][0] as Boolean : false
        log.info "forceScan:  $forceScan"

        log.info("Execute Sca Scan Start")
        def artifacts = searches.artifactsByName(searchPattern, repos.toArray(String[]::new))
        def index = 0g
        for (artifact in artifacts ) {
            log.info "total artifacts number: $artifacts.size"
            log.info "index: $index"
            def artifactRepoPath = artifact.toPath()
            log.info "artifact repo path: $artifactRepoPath"
            scaPlugin.checkArtifactsAlreadyPresent(artifact, forceScan)
            index++
        }
        log.info("Execute Sca Scan Completed")
    }
}