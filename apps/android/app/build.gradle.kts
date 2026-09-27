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


dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2026.09.00")

    implementation(composeBom)
    androidTestImplementation(composeBom)

    implementation("androidx.activity:activity-compose:1.14.0-alpha02")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.11.0")
    implementation("androidx.compose.material3:material3")

    implementation("net.java.dev.jna:jna:5.17.0@aar")
    debugImplementation("androidx.compose.ui:ui-tooling")
    testImplementation("junit:junit:4.13.2")
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
