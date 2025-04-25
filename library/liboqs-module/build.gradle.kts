plugins {
    id("com.android.library")
}

android {
    namespace = "com.oqs.liboqs"
    compileSdk = 31

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")
        ndk {
            abiFilters += listOf("armeabi-v7a", "arm64-v8a", "x86", "x86_64")
        }
        testOptions {
            targetSdk = 35
        }
        lint {
            targetSdk = 35
        }
    }

    buildTypes {
        release {
            isJniDebuggable = true
            isMinifyEnabled = false
            isShrinkResources = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    externalNativeBuild {
        ndkBuild {
            buildStagingDirectory = file("./outputs/ndk-build")
            path = file("jni/Android.mk")
        }
    }

    packaging {
        resources {
            excludes += setOf(
                "META-INF/DEPENDENCIES",
                "META-INF/LICENSE.md",
                "META-INF/LICENSE-notice.md"
            )
        }
    }
    ndkVersion = "28.0.13004108"
}

dependencies {
    androidTestImplementation(libs.androidx.runner)
    androidTestImplementation(libs.androidx.monitor)
    androidTestImplementation(libs.junit.jupiter)
    androidTestImplementation(libs.ext.junit)
}

// Benutzerdefinierte Aufgabe für den NDK-Build
tasks.register("buildNative") {
    doLast {
        val ndkDirectory = android.ndkDirectory.absolutePath
        val ndkBuildPath = "$ndkDirectory/build/ndk-build.cmd" // .cmd für Windows

        // Überprüfung der NDK-Verfügbarkeit
        if (!file(ndkBuildPath).exists()) {
            throw GradleException("NDK build tool not found at: $ndkBuildPath")
        }

        // Überprüfung der Abhängigkeiten (z.B. liboqs.so)
        val abiList = listOf("arm64-v8a", "armeabi-v7a", "x86", "x86_64")
        for (abi in abiList) {
            val libPath = file("jni/jniLibs/$abi/liboqs.so")
            if (!libPath.exists()) {
                throw GradleException("Missing dependency: $libPath")
            }
        }

        // NDK-Build ausführen
        val processBuilder = ProcessBuilder(ndkBuildPath, "-C", file("jni").absolutePath)
        val process = processBuilder.inheritIO().start()
        process.waitFor()

        if (process.exitValue() != 0) {
            throw GradleException("NDK build failed.")
        }
    }
}

// Abhängigkeit des Standard-Builds von der benutzerdefinierten Aufgabe
tasks.named("preBuild").configure {
    dependsOn("buildNative")
}
