# SunLicense — Java Client

Official Java client for [SunLicense](https://sunlicense.com), a licence management and
anti-piracy system for indie software developers.

SunLicense issues, validates and revokes licence keys for Minecraft plugins, Discord bots,
FiveM scripts, desktop apps and other paid software — with marketplace automation for
BuiltByBit and Polymart.

> **Early release.** Licence validation works today. Activations, entitlements and offline
> verification are in active development.

## Install

```xml
<dependency>
  <groupId>com.sunlicense</groupId>
  <artifactId>sunlicense</artifactId>
  <version>0.1.0</version>
</dependency>
```

Gradle:

```groovy
implementation 'com.sunlicense:sunlicense:0.1.0'
```

## Usage

```java
SunLicense client = new SunLicense.Builder()
        .baseUrl("https://your-instance.example.com")
        .token(System.getenv("SUNLICENSE_TOKEN")) // optional
        .build();

SunLicense.Result result = client.validate("LICENCE-KEY-HERE");

if (result.isValid()) {
    getLogger().info("Licence valid");
} else {
    getLogger().warning("Rejected: " + result.getStatus() + " " + result.getBody());
}
```

With extra context:

```java
client.validate("LICENCE-KEY-HERE", Map.of("product", "my-plugin", "host", "server-01"));
```

## Usage statistics

Every 30 minutes, on a background thread, the client can report anonymous usage statistics (product version,
OS, architecture, CPU cores, locale, Java version and platform) for your product's **Analytics** tab:

```java
SunLicenseAnalytics analytics = client.analytics(licenceKey, machineId)
        .productVersion("2.3.1")
        .enabled(config.getBoolean("analytics", true))
        .start();
// free products, no licence: SunLicense.analytics("pa_…")
analytics.close(); // on shutdown
```

It never blocks or fails a validation. Off when your switch says so, with `SUNLICENSE_ANALYTICS=off`, or with
`-Dsunlicense.analytics=false`. What is sent: https://docs.sunlicense.com/guide/sdks#built-in-analytics

Feature usage and bStats-style custom charts (shown on Lite and Standard plans):

```java
analytics.feature("auto-sell");
analytics.simplePie("storage", () -> config.getString("storage"))
         .singleLine("players", () -> server.getOnlinePlayers().size());
```

Every chart type: https://docs.sunlicense.com/guide/product-analytics#feature-usage-and-custom-charts

## Requirements

**Java 11 or newer.** No third-party dependencies — safe to shade into a plugin without
relocation conflicts.

## Other clients

Also available for **JavaScript**, **Python**, **PHP** and **Lua**.

## Links

- Website — https://sunlicense.com
- Documentation — https://docs.sunlicense.hapangama.com
- Issues — https://github.com/sunlicense-com/sunlicense-java/issues

## Licence

MIT © Hapangama
