# build jar stage
FROM docker.io/gradle:7.6-jdk17

RUN apt update && apt install -y python3-pip && pip3 install python-gitlab && pip3 install pyyaml && pip3 install requests && rm -rf /var/lib/apt/lists/*

WORKDIR /base

COPY ./ ./

RUN mkdir -p /gradle-home/.gradle && echo 'nexusUsername=FILL\n\
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

WORKDIR /app

COPY ./ ./

RUN gradle build --build-cache -i -g /gradle-home/.gradle --no-daemon && \
cd build/libs && \
java -Djarmode=layertools -jar app.jar extract && \
#empty file in case snapshot-dependencies is empty
touch snapshot-dependencies/placeholder

# build container stage

# get trivy
RUN wget "${TRIVY_BASEURL}/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" \
  && echo "${TRIVY_CHECKSUM}  trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" | sha256sum -c - \
  && tar xvf "trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz" \

RUN mkdir -p /eps/app && mkdir -p /eps/tmp && chmod -R a+rwx /eps

COPY /app/build/libs/app.jar /eps/app/

WORKDIR /eps/app

RUN mv /app/build/libs/dependencies/ ./ \
  && mv /app/build/libs/spring-boot-loader ./ \
  && mv /app/build/libs/snapshot-dependencies/ ./ \
  && mv /app/build/libs/application/ ./ \
  && mv /app/trivy ./trivy/
  && mv /app/LICENSE ./trivy/
  && chmod +x trivy/trivy
  && rm -rf /app

USER 1001

ENTRYPOINT ["java","-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5084","org.springframework.boot.loader.JarLauncher"]
