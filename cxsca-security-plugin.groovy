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

// curl -i -u admin:password -X POST "http://localhost:8082/artifactory/api/plugins/execute/scaScanCtl?params=excludePattern=com.coupang*;numberOfThreads=4;searchPattern=*.whl;repos=pypi-remote-cache;forceScan=true"

def pluginGroup = 'cleaners'
executions {
    scaScanCtl(groups: [pluginGroup]) { params ->
        // params type seems to be Map<String, List<String>>
        def excludePattern = params['excludePattern'] ? params['excludePattern'][0] as String : ''
        def numberOfThreads = params['numberOfThreads'] ? params['numberOfThreads'][0] as int : 4
        def searchPattern = params['searchPattern'] ? params['searchPattern'][0] as String : ''

        log.info "searchPattern:  $searchPattern"
        // Ensure the given repo list is not empty
        def repos = params?.get('repos')
        if (!repos) {
            log.debug("No repos were given to index.")
            status = 400
            message = "No repos were given to index."
            return
        }
        log.info "repos:  $repos"
        def forceScan = params['forceScan'] ? params['forceScan'][0] as Boolean : false
        log.info "forceScan:  $forceScan"

        log.info("Execute Sca Scan Start")
        def artifacts = searches.artifactsByName(searchPattern, repos.toArray(String[]::new))
        def artifactsSubLists = artifacts.collate(numberOfThreads);
        def excludeArtifacts = searches.artifactsByName(excludePattern, repos.toArray(String[]::new))
        def excludeArtifactsRepoPathList = []
        excludeArtifacts.each { excludedArtifact ->
            def repoPath = excludedArtifact.toPath()
            excludeArtifactsRepoPathList << repoPath
        }

        def requestThreads = []
        artifactsSubLists.eachWithIndex { artifactsSubList, threadIndex ->
            Thread requestThread = new Thread({
                artifactsSubList.eachWithIndex { artifact, index ->
                    log.info "Thread index: $threadIndex"
                    log.info "total artifacts number: $artifactsSubList.size"
                    log.info "index: $index"
                    def artifactRepoPath = artifact.toPath()
                    log.info "artifact repo path: $artifactRepoPath"
                    if (excludeArtifactsRepoPathList.contains(artifactRepoPath)) {
                        return
                    }
                    scaPlugin.checkArtifactsAlreadyPresent(artifact, forceScan)
                }
            })
            requestThreads << requestThread
        }
        requestThreads.each { it.start() }
        requestThreads.each { it.join() }

        log.info("Execute Sca Scan Completed")
    }
}