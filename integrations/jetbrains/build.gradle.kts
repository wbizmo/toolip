plugins {
    id("org.jetbrains.kotlin.jvm") version "2.2.21"
    id("org.jetbrains.intellij.platform") version "2.20.1"
}

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    intellijPlatform {
        intellijIdeaUltimate("2026.2.3")
    }
}

intellijPlatform {
    pluginConfiguration {
        id = "xyz.zivoralabs.toolip.jetbrains"
        name = "Toolip Security"
        version = "0.0.0"
        vendor {
            name = "Zivora Labs"
            url = "https://www.zivoralabs.xyz"
        }
    }
}
