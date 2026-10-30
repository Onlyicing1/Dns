import java.util.Properties

plugins {
    id("com.android.application")
    id("com.chaquo.python")
}

// Read the signing config from keystore.properties if present (CI writes it).
val keystorePropsFile = rootProject.file("keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) keystorePropsFile.inputStream().use { load(it) }
}

android {
    namespace = "com.onlyicing.dnsconsole"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.onlyicing.dnsconsole"
        minSdk = 24
        targetSdk = 34
        versionCode = (System.getenv("VERSION_CODE") ?: "1").toInt()
        versionName = System.getenv("VERSION_NAME") ?: "1.0"

        ndk {
            // Python 3.12+ ships arm64-v8a and x86_64 only.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    if (keystorePropsFile.exists()) {
        signingConfigs {
            create("release") {
                storeFile = rootProject.file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (keystorePropsFile.exists()) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        // advanced_core.py is copied here by the syncPythonSource task below.
        getByName("main") {
            java.srcDirs("src/main/java")
        }
    }
}

chaquopy {
    defaultConfig {
        version = "3.12"
        pip {
            // The app is stdlib-only, so there are no Python dependencies to install.
        }
    }
    sourceSets {
        getByName("main") {
            srcDir(layout.buildDirectory.dir("generated/python"))
        }
    }
}

// Keep a single source of truth: the app bundles the repo-root script verbatim.
val syncPythonSource by tasks.registering(Copy::class) {
    from(rootProject.file("../advanced_core.py"))
    into(layout.buildDirectory.dir("generated/python"))
}

tasks.matching { it.name == "preBuild" }.configureEach {
    dependsOn(syncPythonSource)
}

// Chaquopy's *PythonSources tasks read the generated dir; make the dependency explicit.
tasks.matching { it.name.contains("PythonSources") }.configureEach {
    dependsOn(syncPythonSource)
}

dependencies {
    // Align every kotlin-stdlib artifact (Chaquopy drags in an old jdk7/jdk8 set,
    // which collides with the newer stdlib that androidx pulls in).
    implementation(platform("org.jetbrains.kotlin:kotlin-bom:1.8.22"))
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.activity:activity:1.9.3")
}
