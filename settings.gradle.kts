pluginManagement {
    repositories {
        maven {
            url
            nexusBaseUrl + '/repository/public/'
        }
    }
}

rootProject.name = 'trivy-rest-client'

dependencyResolutionManagement {
    repositories {
        maven {
            credentials {
                username nexusUsername
                password nexusPassword
            }
            url nexusBaseUrl + '/repository/public'
        }
    }
}
