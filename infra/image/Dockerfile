# build jar stage
FROM docker.io/gradle:7.6-jdk17

RUN apt update && apt install -y python3-pip && pip3 install python-gitlab && pip3 install pyyaml && pip3 install requests && rm -rf /var/lib/apt/lists/*

WORKDIR /base

COPY ./ ./

RUN mkdir -p /gradle-home/.gradle && echo 'nexusUsername=deployment\n\
nexusPassword=FILL\n\
nexusBaseUrl=FILL\n\
systemProp.https.proxyHost=FILL\n\
systemProp.https.proxyPort=FILL\n\
systemProp.http.proxyHost=FILL\n\
systemProp.http.proxyPort=FILL\n\
\n' > /gradle-home/.gradle/gradle.properties && \
gradle build -g /gradle-home/.gradle --no-daemon && \
chmod 777 -R /gradle-home/.gradle && \
rm -rf /base

RUN rm -rf /gradle-home/.gradle/daemon && \
rm -rf /gradle-home/.gradle/workers && \
rm -rf /gradle-home/.gradle/notifications && \
rm -rf /gradle-home/.gradle/native

VOLUME ["/gradle-home/.gradle"]

