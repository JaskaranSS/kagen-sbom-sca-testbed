plugins {
    kotlin("jvm") version "1.4.0"
}

val poiVersion = "4.1.0"

dependencies {
    implementation("org.apache.poi:poi-ooxml:$poiVersion")
    implementation("org.jsoup:jsoup:1.13.1")
    implementation(libs.okhttp)
    testImplementation("org.junit.jupiter:junit-jupiter:5.6.2")
}
