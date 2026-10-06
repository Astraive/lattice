plugins {
    id("com.android.application") version "9.4.1" apply false
    id("com.android.library") version "9.4.1" apply false
    id("org.jetbrains.kotlin.plugin.compose") version "2.4.20" apply false
}

allprojects {
    dependencyLocking {
        lockAllConfigurations()
    }
    // Patch vulnerable transitive Android lint-tool dependencies in every locked configuration.

    configurations.configureEach {
        resolutionStrategy.force(
            "org.apache.commons:commons-lang3:3.18.0",
            "org.apache.httpcomponents:httpclient:4.5.13",
            "org.bouncycastle:bcpkix-jdk18on:1.85",
            "org.bouncycastle:bcprov-jdk18on:1.85",
            "org.bouncycastle:bcutil-jdk18on:1.85",
        )
    }
}
