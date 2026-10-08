plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
}

android {
    namespace = "com.astraive.lattice"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.astraive.lattice"
        minSdk = 26
        targetSdk = 37
        versionCode = 1
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    sourceSets {
        getByName("test").resources.directories.add("../../../protocol/vectors")
    }
}

tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    outputs.cacheIf("Required tests must execute on every run") { false }
    outputs.upToDateWhen { false }
    val testTaskPath = path
    val testTaskLogger = logger
    addTestListener(
        object : org.gradle.api.tasks.testing.TestListener {
            override fun beforeSuite(suite: org.gradle.api.tasks.testing.TestDescriptor) = Unit

            override fun afterSuite(
                suite: org.gradle.api.tasks.testing.TestDescriptor,
                result: org.gradle.api.tasks.testing.TestResult,
            ) {
                if (suite.parent == null) {
                    testTaskLogger.lifecycle("$testTaskPath: ${result.testCount} tests")
                    if (result.testCount == 0L) {
                        throw GradleException("$testTaskPath discovered no tests")
                    }
                }
            }

            override fun beforeTest(test: org.gradle.api.tasks.testing.TestDescriptor) = Unit

            override fun afterTest(
                test: org.gradle.api.tasks.testing.TestDescriptor,
                result: org.gradle.api.tasks.testing.TestResult,
            ) = Unit
        },
    )
}


dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.14.0-alpha02")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.compose.material3:material3")
    implementation(project(":ui-android"))

    implementation("net.java.dev.jna:jna:5.17.0@aar")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("org.json:json:20250517")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test:runner:1.7.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}

val rustWorkspace = rootProject.projectDir.resolve("../..").canonicalFile
val rustJniLibs = layout.projectDirectory.dir("src/main/jniLibs").asFile
val hostRustLibrary = rustWorkspace.resolve(
    when {
        System.getProperty("os.name").lowercase().contains("win") -> "target/debug/lattice_uniffi.dll"
        System.getProperty("os.name").lowercase().contains("mac") -> "target/debug/liblattice_uniffi.dylib"
        else -> "target/debug/liblattice_uniffi.so"
    },
)
val buildUniFfiBindingLibrary = tasks.register<Exec>("buildUniFfiBindingLibrary") {
    group = "build"
    description = "Builds the host UniFFI library used to regenerate Kotlin bindings."
    workingDir = rustWorkspace
    inputs.dir(rustWorkspace.resolve("crates"))
    inputs.file(rustWorkspace.resolve("Cargo.toml"))
    inputs.file(rustWorkspace.resolve("Cargo.lock"))
    outputs.file(hostRustLibrary)
    outputs.cacheIf("Required native library must be rebuilt") { false }
    outputs.upToDateWhen { false }
    commandLine("cargo", "build", "--locked", "-p", "lattice-uniffi")
}
val kotlinBindings = layout.projectDirectory.file("src/main/kotlin/uniffi/lattice_uniffi/lattice_uniffi.kt")
val generateUniFfiBindings = tasks.register<Exec>("generateUniFfiBindings") {
    group = "build"
    description = "Regenerates the checked-in Kotlin bindings from lattice-uniffi."
    dependsOn(buildUniFfiBindingLibrary)
    workingDir = rustWorkspace
    inputs.file(hostRustLibrary)
    inputs.file(rustWorkspace.resolve("crates/lattice-uniffi/uniffi.toml"))
    outputs.file(kotlinBindings)
    outputs.cacheIf("UniFFI bindings must be regenerated") { false }
    outputs.upToDateWhen { false }
    commandLine(
        "cargo",
        "run",
        "--locked",
        "-p",
        "lattice-uniffi",
        "--features",
        "cli",
        "--bin",
        "uniffi-bindgen",
        "--",
        "generate",
        "--library",
        "--language",
        "kotlin",
        hostRustLibrary.absolutePath,
        "--out-dir",
        layout.projectDirectory.dir("src/main/kotlin").asFile.absolutePath,
    )
}

val buildRustMobile = tasks.register<Exec>("buildRustMobile") {
    group = "build"
    description = "Builds the shared UniFFI Rust library for supported Android ABIs."
    workingDir = rustWorkspace
    inputs.dir(rustWorkspace.resolve("crates"))
    inputs.file(rustWorkspace.resolve("Cargo.toml"))
    inputs.file(rustWorkspace.resolve("Cargo.lock"))
    outputs.dir(rustJniLibs)
    outputs.cacheIf("Android Rust libraries must be rebuilt") { false }
    outputs.upToDateWhen { false }
    commandLine(
        "cargo",
        "ndk",
        "-t",
        "arm64-v8a",
        "-t",
        "x86_64",
        "-o",
        rustJniLibs.absolutePath,
        "build",
        "-p",
        "lattice-uniffi",
        "--release",
    )
}
buildRustMobile.configure {
    dependsOn(generateUniFfiBindings)
}

tasks.named("preBuild").configure {
    dependsOn(buildRustMobile)
}
