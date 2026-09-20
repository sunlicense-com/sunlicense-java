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
  <version>0.0.1</version>
</dependency>
```

Gradle:

```groovy
implementation 'com.sunlicense:sunlicense:0.0.1'
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
