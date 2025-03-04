plugins {
    id(ThunderbirdPlugins.Library.android)
}
android {
    namespace = "com.core.pqc_extension"
}
dependencies{
    implementation(project(":library:liboqs-module"))
    implementation(libs.junit.junit)
    testImplementation("junit:junit:4.13.2")
}
