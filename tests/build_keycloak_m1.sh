#!/bin/zsh

cd /tmp
git clone git@github.com:keycloak/keycloak-containers.git
cd keycloak-containers/server
git checkout 16.1.0
docker build -t "jboss/keycloak:16.1.0" .
