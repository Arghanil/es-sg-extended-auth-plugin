# Elasticsearch Search Guard Extended Auth Plugin
This plugin makes up for the security limitation that search-guard has in terms of exposing nodes info.

## Description
Search Guard 1.7.3.0 has the following as one of the [limitations](https://github.com/floragunncom/search-guard/tree/a031c6e62b0dd612bd60cf4ab13fedd212cf4913#limitations) – Currently monitoring of the cluster needs no authentication and is allowed always (this may change in the future)

I.e. If Elasticsearch node info is accessed using URI as http://hostname:9200/_nodes, ALL authenticated users are able to see restricted information.

The ``es-sg-extended-auth-plugin`` enforces role based access to node info (using _node query_).

> **Note:** This solution is a patch fix for the inefficiencies of search-guard version <2.x

## Usage
* Download the latest plugin jar from the release(s) under [tags](/tags)
* Install as a plugin to your elasticsearch nodes using ``./bin/plugin --url file:///<path to the jar file> --install sg-extended-auth``

## Configuration
The role based access to node info (using _node query_) can be further configured by adding the following configuration to elasticsearch.yml –
```
searchguard.node_info.role: admin,dba
```
If no configuration is provided, the filter inside will verify against a default role "admin"

## Building
* Clone the project and run `gradle clean build`
* The JAR is built and the pom file is created inside $rootDir/repo

## Note
* This solution is a patch fix for the inefficiencies of search-guard version <2.x. This is presumably taken care in the latest release.
* Tools like Big Desk uses _node query_ heavily to load dashboards. In order to get the Big Desk dashboard working, Big Desk must be run with user with a role that is configured for _node query_ access.
