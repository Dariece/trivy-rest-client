# Trivy Rest Client
A simple wrapper to start trivy cli scan jobs from remote environment like in CI-Pipeline;

## Pre conditions
Start trivy server with actual CVE database.

### Local installation (Ubuntu)
see https://aquasecurity.github.io/trivy/v0.38/getting-started/installation/#debianubuntu-official \
`sudo apt-get install wget apt-transport-https gnupg lsb-release` \
`wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | gpg --dearmor | sudo tee /usr/share/keyrings/trivy.gpg > /dev/null` \
`echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list` \
`sudo apt-get update` \
`sudo apt-get install trivy`

### Local installation (Docker)
see https://aquasecurity.github.io/trivy/v0.38/getting-started/installation/#use-container-image \


### Local startup
(On WSL only with WSL2)\
Prepare trivy:
```
./gradlew :downloadTrivyBin
tar xvf trivy\"trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"
chmod +x -R trivy
```

Run in server mode port 9000: \
```bash
./trivy server --listen 0.0.0.0:9000 --cache-dir /appl/tmp/trivy-client/cache --cache-backend fs -d --skip-db-update
```

Run in client mode: \
```
./trivy sbom -f json --timeout 1m -d -v --scanners vuln --vuln-type library --server "http://0.0.0.0:9000" --exit-code 3 /appl/repo/trivy-rest-client/src/test/resources/sbom.json -o /appl/tmp/trivy-client/vulnerability-sbom-test-local-bec7c176-06db-4d76-8247-6686b73d761d-trivy-report.json
```

## Usage app
Start application local: \
```./gradlew bootRun --args='--spring.profiles.active=local'```
