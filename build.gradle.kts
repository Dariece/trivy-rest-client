plugins {
    id 'org.springframework.boot' version "3.0.2"
    id 'io.spring.dependency-management' version '1.1.0'
    id 'com.gorylenko.gradle-git-properties' version '2.4.0'
    `java`
}

apply plugin: 'io.spring.dependency-management'

group = 'de.daniel.marlinghaus.trivy'
version = '0.0.1'
sourceCompatibility = '17'
targetCompatibility = '17'
compileJava.options.encoding = 'UTF-8'

repositories {
    maven {
        credentials {
            username nexusUsername
            password nexusPassword
        }
        url nexusBaseUrl +'/repository/public/'
    }
    mavenCentral()
}

configurations {
    compileOnly {
        extendsFrom annotationProcessor
    }
}

sourceSets {
    main.java.srcDirs += ["src/main/java", "build/generated"]
}

dependencies {
    //annotation processors
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")
    annotationProcessor("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")

    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.apache.commons:commons-lang3")

    testImplementation("org.springframework.boot:spring-boot-starter-test")
}

dependencyManagement {
    imports {
        mavenBom(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES)
    }
}

bootJar {
    archiveFileName = 'app.jar'
    manifest {
        attributes 'Implementation-Version': project.version, 'Implementation-Title': project.group.toString().substring(project.group.toString().length() - 3).toUpperCase()
    }
}

bootRun {
    if (project.hasProperty('args')) {
        args project.args.split(',')
    }
}

test {
    useJUnitPlatform()
    afterTest { desc, result ->
        logger.quiet "Executing test ${desc.name} [${desc.className}] with result: ${result.resultType}"
    }
}

tasks.withType(JavaCompile) {
    options.compilerArgs << '-Xlint:-deprecation'
}

springBoot {
    buildInfo()
}

//tasks.build.doLast() {
//    copy {
//        from file('pdftoolbox/profiles')
//        into file('build/pdftoolbox/profiles')
//    }
//
//    copy {
//        from file('pdftoolbox/test.pdf')
//        into file('build/pdftoolbox/')
//    }
//}
