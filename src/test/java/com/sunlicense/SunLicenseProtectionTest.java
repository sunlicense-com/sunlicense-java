package com.sunlicense;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.ByteArrayOutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.Signature;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Supplier;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.sun.net.httpserver.HttpServer;

class SunLicenseProtectionTest {
    static final String KEY = "K7QX-M2PD-9HWT-R4CN";
    static final byte[] PRODUCT_KEY = random(32);
    static final String UNLOCK = Base64.getEncoder().encodeToString(PRODUCT_KEY);

    @TempDir
    Path dir;

    final MutableClock clock = new MutableClock(Instant.parse("2026-11-04T12:00:00Z"));

    SunLicenseProtection.Builder builder() {
        return SunLicenseProtection.builder().licenseKey(KEY).fingerprint("paper-1").cacheDirectory(dir)
                .clock(clock).machine(() -> "machine-a");
    }

    /** Seals like validation's seal endpoint (format in the SDK's {@code open}). */
    static String seal(byte[] key, byte[] data, Map<String, String> digests) throws Exception {
        StringBuilder json = new StringBuilder("{\"v\":1,\"data\":\"").append(Base64.getEncoder().encodeToString(data)).append('"');
        if (digests != null) {
            json.append(",\"digests\":{");
            int i = 0;
            for (Map.Entry<String, String> d : digests.entrySet()) {
                json.append(i++ == 0 ? "" : ",").append('"').append(d.getKey()).append("\":\"").append(d.getValue()).append('"');
            }
            json.append('}');
        }
        json.append('}');
        byte[] nonce = random(12);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        c.updateAAD("SLS1".getBytes(StandardCharsets.US_ASCII));
        byte[] ct = c.doFinal(json.toString().getBytes(StandardCharsets.UTF_8));
        byte[] out = new byte[12 + ct.length];
        System.arraycopy(nonce, 0, out, 0, 12);
        System.arraycopy(ct, 0, out, 12, ct.length);
        return "SLS1." + Base64.getUrlEncoder().withoutPadding().encodeToString(out);
    }

    static byte[] random(int n) {
        byte[] b = new byte[n];
        new SecureRandom().nextBytes(b);
        return b;
    }

    static String sha(byte[] b) {
        return SunLicenseProtection.hex(SunLicenseProtection.sha256(b));
    }

    // ---- core unlock ----

    @Test
    void validAnswerUnlocksAndRejectionLocksAgain() throws Exception {
        SunLicenseProtection p = builder().build();
        String sealed = seal(PRODUCT_KEY, "core".getBytes(StandardCharsets.UTF_8), null);
        assertThat(p.unlocked()).isFalse();
        assertThatThrownBy(() -> p.unseal(sealed)).isInstanceOf(SunLicenseProtection.Locked.class);

        p.accept("{\"valid\":true,\"code\":\"VALID\",\"unlock\":\"" + UNLOCK + "\"}");
        assertThat(new String(p.unseal(sealed), StandardCharsets.UTF_8)).isEqualTo("core");

        p.accept("{\"valid\":false,\"status\":400,\"code\":\"SUSPENDED\"}");
        assertThat(p.unlocked()).isFalse();
        assertThatThrownBy(() -> p.unseal(sealed)).isInstanceOf(SunLicenseProtection.Locked.class);
        assertThat(builder().build().unlocked()).as("the cache is gone too").isFalse();
    }

    @Test
    void validAnswerWithoutUnlockKeepsTheOneItHas() throws Exception {
        SunLicenseProtection p = builder().build();
        p.accept(true, UNLOCK);
        p.accept("{\"valid\":true,\"code\":\"VALID\"}");
        assertThat(p.unlocked()).isTrue();
        p.accept("not json");
        p.accept("{\"status\":503}");
        assertThat(p.unlocked()).as("no answer is not a no").isTrue();
    }

    @Test
    void dataSealedForAnotherProductStaysLocked() throws Exception {
        SunLicenseProtection p = builder().build();
        p.accept(true, UNLOCK);
        assertThatThrownBy(() -> p.unseal(seal(random(32), new byte[] {1}, null))).isInstanceOf(SunLicenseProtection.Locked.class)
                .hasMessageContaining("another product");
        assertThatThrownBy(() -> p.unseal("garbage")).isInstanceOf(SunLicenseProtection.Locked.class);
    }

    @Test
    void cachedUnlockSurvivesARestartForSevenDaysOnThisMachineOnly() throws Exception {
        builder().build().accept(true, UNLOCK);
        String sealed = seal(PRODUCT_KEY, new byte[] {7}, null);

        clock.advance(Duration.ofDays(6));
        assertThat(builder().build().unseal(sealed)).containsExactly(7);
        assertThat(builder().machine(() -> "machine-b").build().unlocked()).as("copied to another machine").isFalse();
        assertThat(builder().fingerprint("paper-2").build().unlocked()).as("another machine id").isFalse();
        assertThat(builder().licenseKey("AAAA-BBBB-CCCC-DDDD").build().unlocked()).as("another license").isFalse();
        assertThat(builder().cacheDirectory(null).build().unlocked()).isFalse();

        clock.advance(Duration.ofDays(1).plusMinutes(1));
        assertThat(builder().build().unlocked()).as("older than 7 days").isFalse();
    }

    @Test
    void cacheFromTheFutureIsIgnored() {
        builder().build().accept(true, UNLOCK);
        clock.advance(Duration.ofHours(-1));
        assertThat(builder().build().unlocked()).as("clock turned back").isFalse();
    }

    @Test
    void cacheFileHoldsNoPlainKey() throws Exception {
        builder().build().accept(true, UNLOCK);
        try (var files = Files.list(dir)) {
            List<Path> all = files.collect(java.util.stream.Collectors.toList());
            assertThat(all).hasSize(1);
            String text = Files.readString(all.get(0));
            assertThat(text).startsWith("SLC1.").doesNotContain(UNLOCK).doesNotContain(KEY);
        }
    }

    @Test
    void anotherLicenseKeyDropsTheUnlockInMemory() {
        SunLicenseProtection p = builder().build();
        p.accept(true, UNLOCK);
        p.license(KEY, "paper-1");
        assertThat(p.unlocked()).isTrue();
        p.license("AAAA-BBBB-CCCC-DDDD", "paper-1");
        assertThat(p.unlocked()).isFalse();
    }

    @Test
    void unsealedJarLoadsItsClasses() throws Exception {
        // The test's own compiled class stands in for a sealed core class.
        String name = Core.class.getName().replace('.', '/') + ".class";
        byte[] classBytes;
        try (var in = Core.class.getClassLoader().getResourceAsStream(name)) {
            classBytes = in.readAllBytes();
        }
        ByteArrayOutputStream jar = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(jar)) {
            zip.putNextEntry(new ZipEntry(name));
            zip.write(classBytes);
            zip.putNextEntry(new ZipEntry("core.txt"));
            zip.write("hello".getBytes(StandardCharsets.UTF_8));
        }
        SunLicenseProtection p = builder().build();
        p.accept(true, UNLOCK);
        byte[] core = p.unseal(seal(PRODUCT_KEY, jar.toByteArray(), null));

        // Parent = platform loader, so the class can only come from the sealed jar.
        ClassLoader loader = SunLicenseProtection.classLoader(core, ClassLoader.getPlatformClassLoader());
        Class<?> c = loader.loadClass(Core.class.getName());
        assertThat(c.getClassLoader()).isSameAs(loader);
        @SuppressWarnings("unchecked")
        Supplier<String> s = (Supplier<String>) c.getDeclaredConstructor().newInstance();
        assertThat(s.get()).isEqualTo("core running");
        assertThat(loader.getResourceAsStream("core.txt").readAllBytes()).isEqualTo("hello".getBytes(StandardCharsets.UTF_8));
    }

    public static final class Core implements Supplier<String> {
        @Override
        public String get() {
            return "core running";
        }
    }

    // ---- offline .lic unlock claim ----

    @Test
    void offlineFileCarriesTheUnlock() throws Exception {
        KeyPair keys = generateKeys();
        String pub = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
        String lic = sign(keys, offline(KEY, "\"2026-12-01T00:00:00Z\"", UNLOCK));
        SunLicenseProtection p = builder().build();
        assertThat(p.acceptOffline(lic, pub)).isTrue();
        assertThat(p.unseal(seal(PRODUCT_KEY, new byte[] {3}, null))).containsExactly(3);
        assertThat(builder().build().unlocked()).as("the .lic isn't copied into the cache").isFalse();
    }

    @Test
    void unusableOfflineFilesGiveNoUnlock() throws Exception {
        KeyPair keys = generateKeys();
        String pub = Base64.getEncoder().encodeToString(keys.getPublic().getEncoded());
        SunLicenseProtection p = builder().build();
        assertThat(p.acceptOffline(sign(keys, offline(KEY, "\"2026-11-01T00:00:00Z\"", UNLOCK)), pub)).as("expired").isFalse();
        assertThat(p.acceptOffline(sign(keys, offline("AAAA-BBBB-CCCC-DDDD", "null", UNLOCK)), pub)).as("other key").isFalse();
        assertThat(p.acceptOffline(sign(keys, offline(KEY, "null", null)), pub)).as("no claim").isFalse();
        assertThat(p.acceptOffline(sign(generateKeys(), offline(KEY, "null", UNLOCK)), pub)).as("forged").isFalse();
        assertThat(p.unlocked()).isFalse();
    }

    static KeyPair generateKeys() throws Exception {
        return java.security.KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    }

    static String offline(String key, String expiresAt, String unlock) {
        return "{\"format\":\"sunlicense-offline/1\",\"licenseKey\":\"" + key + "\",\"policy\":{\"name\":\"Pro\",\"expiresAt\":"
                + expiresAt + "},\"issuedAt\":\"2026-11-01T10:00:00Z\",\"refreshAfter\":\"2026-11-30T10:00:00Z\""
                + (unlock == null ? "" : ",\"unlock\":\"" + unlock + "\"") + "}";
    }

    static String sign(KeyPair keys, String json) throws Exception {
        byte[] payload = json.getBytes(StandardCharsets.UTF_8);
        Signature s = Signature.getInstance("Ed25519");
        s.initSign(keys.getPrivate());
        s.update(payload);
        var b64 = Base64.getUrlEncoder().withoutPadding();
        return b64.encodeToString(payload) + "." + b64.encodeToString(s.sign());
    }

    // ---- integrity ----

    @Test
    void integrityComparesTheSealedDigestsAndGoesWithTheNextCheck() throws Exception {
        Path classes = dir.resolve("classes");
        Files.createDirectories(classes.resolve("com/example"));
        Files.write(classes.resolve("com/example/Main.class"), new byte[] {1, 2, 3});
        Files.write(classes.resolve("com/example/Guard.class"), new byte[] {4, 5, 6});
        Map<String, String> digests = new LinkedHashMap<>();
        digests.put("com/example/Main.class", sha(new byte[] {1, 2, 3}));
        digests.put("com/example/Guard.class", sha(new byte[] {4, 5, 6}));

        SunLicenseProtection p = builder().cacheDirectory(null).build();
        assertThat(p.validateFields()).isEmpty();
        p.accept(true, UNLOCK);
        p.unseal(seal(PRODUCT_KEY, new byte[] {0}, digests));
        assertThat(p.digests()).containsAllEntriesOf(digests);

        assertThat(p.integrity(classes)).isEqualTo("OK");
        assertThat(p.validateFields()).containsExactly(Map.entry("integrity", "OK"));

        Files.write(classes.resolve("com/example/Guard.class"), new byte[] {9});   // the license check patched out
        assertThat(p.integrity(classes)).isEqualTo("MODIFIED");
        assertThat(p.validateFields()).containsEntry("integrity", "MODIFIED")
                .containsEntry("integrityDetail", "1 changed: com/example/Guard.class");

        Files.delete(classes.resolve("com/example/Main.class"));
        assertThat(p.integrity(classes)).isEqualTo("MODIFIED");
        assertThat(p.validateFields().get("integrityDetail")).contains("Main.class (missing)");
    }

    @Test
    void integrityReadsAJarAndAClassLoader() throws Exception {
        Path jar = dir.resolve("plugin.jar");
        try (ZipOutputStream zip = new ZipOutputStream(Files.newOutputStream(jar))) {
            zip.putNextEntry(new ZipEntry("a/B.class"));
            zip.write(new byte[] {42});
        }
        SunLicenseProtection p = builder().cacheDirectory(null).build();
        p.accept(true, UNLOCK);
        p.unseal(seal(PRODUCT_KEY, new byte[] {0}, Map.of("a/B.class", sha(new byte[] {42}))));
        assertThat(p.integrity(jar)).isEqualTo("OK");
        try (var loader = new java.net.URLClassLoader(new java.net.URL[] {jar.toUri().toURL()}, null)) {
            assertThat(p.integrity(loader)).isEqualTo("OK");
        }
        assertThat(p.integrity(name -> null, Map.of())).as("nothing sealed with digests").isNull();
    }

    @Test
    void integrityDetailStaysShort() {
        List<String> many = new ArrayList<>();
        for (int i = 0; i < 40; i++) {
            many.add("com/example/some/long/package/Name" + i + ".class");
        }
        String d = SunLicenseProtection.detail(many);
        assertThat(d).hasSizeLessThanOrEqualTo(200).startsWith("40 changed: ").endsWith(" more");
    }

    // ---- notice ----

    @Test
    void noticeNamesProductOwnerAndMaskedKeyOnly() {
        String n = builder().product("MyPlugin", "Example Studio").terms("https://example.com/terms").build().notice();
        assertThat(n).isEqualTo("MyPlugin is licensed software by Example Studio. License K7QX-XXXX-XXXX-XXXX. Terms: https://example.com/terms");
        assertThat(SunLicenseProtection.builder().build().notice()).isEqualTo("This product is licensed software. License (none).");
        assertThat(SunLicenseProtection.mask("ABCDEFGH")).isEqualTo("ABCDXXXX");
    }

    // ---- protected files and the client, against a stub server ----

    @Test
    void clientSendsIntegrityKeepsTheUnlockAndDownloadsProtectedFiles() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        List<Map<String, String>> fileHeaders = new CopyOnWriteArrayList<>();
        String[] answer = {"{\"valid\":true,\"status\":200,\"code\":\"VALID\",\"unlock\":\"" + UNLOCK + "\"}"};
        int[] status = {200};
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v2/license/validate", ex -> {
            bodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = answer[0].getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status[0], out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.createContext("/api/v2/protected-files/", ex -> {
            fileHeaders.add(Map.of("path", ex.getRequestURI().getRawPath(),
                    "auth", String.valueOf(ex.getRequestHeaders().getFirst("Authorization")),
                    "license", String.valueOf(ex.getRequestHeaders().getFirst("X-License-Key")),
                    "fingerprint", String.valueOf(ex.getRequestHeaders().getFirst("X-Fingerprint"))));
            boolean known = ex.getRequestURI().getRawPath().endsWith("/rules.dat");
            byte[] out = (known ? "RULES" : "{\"code\":\"NOT_FOUND\"}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(known ? 200 : 404, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            SunLicense client = new SunLicense.Builder().baseUrl(url).token("slk_test")
                    .protection(builder().productCode("myplugin")).build();
            SunLicenseProtection p = client.protection();
            SunLicense.Result r = client.validate(KEY, Map.of("host", "paper-1"));
            assertThat(r.isValid()).isTrue();
            assertThat(p.unlocked()).isTrue();
            assertThat(bodies.get(0)).doesNotContain("integrity");

            Path classes = dir.resolve("c");
            Files.createDirectories(classes);
            Files.write(classes.resolve("X.class"), new byte[] {1});
            p.unseal(seal(PRODUCT_KEY, new byte[] {0}, Map.of("X.class", sha(new byte[] {2}))));
            assertThat(p.integrity(classes)).isEqualTo("MODIFIED");
            client.validate(KEY, Map.of("host", "paper-1"));
            assertThat(bodies.get(1)).contains("\"integrity\":\"MODIFIED\"").contains("\"integrityDetail\":\"1 changed: X.class\"");

            assertThat(p.protectedFile("rules.dat")).isEqualTo("RULES".getBytes(StandardCharsets.UTF_8));
            assertThat(fileHeaders.get(0)).containsEntry("path", "/api/v2/protected-files/myplugin/rules.dat")
                    .containsEntry("auth", "Bearer slk_test").containsEntry("license", KEY).containsEntry("fingerprint", "paper-1");
            assertThatThrownBy(() -> p.protectedFile("other file.dat")).isInstanceOf(SunLicenseProtection.Refused.class)
                    .hasMessageContaining("404").hasMessageContaining("NOT_FOUND");
            assertThat(fileHeaders.get(1).get("path")).isEqualTo("/api/v2/protected-files/myplugin/other%20file.dat");

            status[0] = 400;
            answer[0] = "{\"valid\":false,\"status\":400,\"code\":\"REVOKED\"}";
            assertThat(client.validate(KEY, Map.of("host", "paper-1")).isValid()).isFalse();
            assertThatThrownBy(() -> p.unseal(seal(PRODUCT_KEY, new byte[] {0}, null)))
                    .isInstanceOf(SunLicenseProtection.Locked.class);
        } finally {
            server.stop(0);
        }
    }

    @Test
    void oldAppsSendTheSameRequestAsBefore() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/api/v2/license/validate", ex -> {
            bodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] out = "{\"valid\":true,\"status\":200,\"code\":\"VALID\"}".getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, out.length);
            ex.getResponseBody().write(out);
            ex.close();
        });
        server.start();
        try {
            String url = "http://127.0.0.1:" + server.getAddress().getPort();
            new SunLicense.Builder().baseUrl(url).token("slk_test").build().validate(KEY, Map.of("host", "fp"));
            SunLicense withProtection = new SunLicense.Builder().baseUrl(url).token("slk_test")
                    .protection(SunLicenseProtection.builder().cacheDirectory(dir)).build();
            assertThat(withProtection.validate(KEY, Map.of("host", "fp")).isValid()).isTrue();
            assertThat(withProtection.protection().unlocked()).isFalse();
            assertThat(bodies.get(0)).isEqualTo("{\"license\":\"" + KEY + "\",\"host\":\"fp\"}");
            assertThat(bodies.get(1)).as("no integrity checked yet: the same request").isEqualTo(bodies.get(0));
            try (var files = Files.list(dir)) {
                assertThat(files.count()).as("nothing cached without an unlock").isZero();
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    void protectedFileOutageIsAnIOExceptionNotARefusal() {
        SunLicenseProtection p = builder().productCode("myplugin")
                .transport((url, headers) -> new SunLicenseProtection.Response(503, new byte[0])).build();
        assertThatThrownBy(() -> p.protectedFile("rules.dat")).isInstanceOf(java.io.IOException.class)
                .isNotInstanceOf(SunLicenseProtection.Refused.class);
    }

    @Test
    @SuppressWarnings("unchecked")
    void jsonReaderHandlesTheAnswersShapes() {
        Object v = SunLicenseProtection.Json.parse(
                "{ \"valid\" : true, \"n\": -1.5e2, \"a\": [1, \"x\\u0041\\n\", null, {}], \"machines\": {\"used\": 1, \"max\": null} }");
        assertThat(v).isInstanceOf(Map.class);
        Map<?, ?> m = (Map<?, ?>) v;
        assertThat(m.get("valid")).isEqualTo(true);
        assertThat(m.get("n")).isEqualTo(-150.0);
        assertThat((List<Object>) m.get("a")).containsExactly(1L, "xA\n", null, Map.of());
        assertThatThrownBy(() -> SunLicenseProtection.Json.parse("{\"a\":1} x")).isInstanceOf(IllegalArgumentException.class);
    }

    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
