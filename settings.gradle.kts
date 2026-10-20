plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
  id("com.gradleup.nmcp.settings") version "1.6.2"
}
rootProject.name = "acl"

nmcpSettings {
  centralPortal {
    username = providers.gradleProperty("centralPortalUsername")
    password = providers.gradleProperty("centralPortalPassword")
    // Pass -PcentralPortalPublishingType=USER_MANAGED to upload and validate without releasing.
    publishingType = providers.gradleProperty("centralPortalPublishingType").orElse("AUTOMATIC")
  }
}
