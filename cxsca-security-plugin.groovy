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

// curl -i -u admin:password -X POST "http://localhost:8082/artifactory/api/plugins/execute/scaScanCtl?params=excludePattern=com.coupang*;searchPattern=*.whl;repos=pypi-remote-cache;forceScan=true;numberOfBatch=1024"

def pluginGroup = 'cleaners'
executions {
    scaScanCtl(groups: [pluginGroup]) { params ->
        log.info("Start parsing parameters form REST API call")
        // params type seems to be Map<String, List<String>>
        def excludePattern = params['excludePattern'] ? params['excludePattern'][0] as String : ''
        def searchPattern = params['searchPattern'] ? params['searchPattern'][0] as String : ''
        log.info("Parameter excludePattern: $excludePattern")
        log.info("Parameter searchPattern:  $searchPattern")
        // Ensure the given repo list is not empty
        def repos = params?.get('repos')
        if (!repos) {
            log.debug("No repos were given to index.")
            status = 400
            message = "No repos were given to index."
            return
        }
        log.info("Parameter repos:  $repos")
        def forceScan = params['forceScan'] ? params['forceScan'][0] as Boolean : false
        log.info("Parameter forceScan:  $forceScan")
        def numberOfBatch = params['numberOfBatch'] ? params['numberOfBatch'][0] as int : 1024
        log.info("Parameter numberOfBatch: $numberOfBatch")
        log.info("End parsing parameters form REST API call")

        log.info("Execute Sca Scan Start")
        def allArtifacts = searches.artifactsByName(searchPattern, repos.toArray(String[]::new))
        def numberOfAllArtifacts = allArtifacts.size()
        log.info("All artifacts number: $numberOfAllArtifacts")
        def excludeArtifacts = searches.artifactsByName(excludePattern, repos.toArray(String[]::new))
        def numberOfExcludedArtifacts = excludeArtifacts.size()
        log.info("Excluded artifacts number: $numberOfExcludedArtifacts")
        def artifacts = allArtifacts.toSet().minus(excludeArtifacts.toSet()).toList()
        def numberOfArtifacts =  artifacts.size()
        log.info("Artifacts to be scaned number: $numberOfArtifacts")

        def artifactsList = artifacts.collate(numberOfBatch);
        artifactsList.eachWithIndex { artifactsSubList, index ->
            scaPlugin.scanArtifactsConcurrently(artifactsSubList, forceScan)
            def finishedPercent = (artifactsSubList.size() + numberOfBatch * index) * 100 / numberOfArtifacts
            log.info("$finishedPercent Percent finished.")
        }
        log.info("Execute Sca Scan Completed")
    }
}