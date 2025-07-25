import org.gradle.api.JavaVersion

object ThunderbirdProjectConfig {

    val javaCompatibilityVersion = JavaVersion.VERSION_11

    const val androidSdkMin = 26
    const val androidSdkTarget = 34
    const val androidSdkCompile = 35
}
