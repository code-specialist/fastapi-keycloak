# Apple MacBook M1 issues

In case you're using a  current Apple MacBook with M1 CPU, you might encounter the issue that Keycloak just won't start (local testing purposes). We resolved this issues 
ourselves by rebuilding the image locally. Doing so might look like the following:

```shell
#!/bin/zsh

cd /tmp
git clone git@github.com:keycloak/keycloak-containers.git
cd keycloak-containers/server
git checkout 16.1.0
docker build -t "jboss/keycloak:16.1.0" .
```