package com.sunlicense;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URI;
import java.net.URL;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.zip.ZipInputStream;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Protection for a licensed product (spec "product setup and protection" §4.6, §4.7, §4.9): core unlock, tamper
 * reports, the ownership notice and protected files.
 *
 * <pre>{@code
 * SunLicenseProtection protection = SunLicenseProtection.builder()
 *         .apiKey(apiKey).licenseKey(licenseKey).fingerprint(machineId)
 *         .product("MyPlugin", "Example Studio").terms("https://example.com/terms")
 *         .productCode("myplugin")                 // for protected files
 *         .cacheDirectory(dataFolder)              // where the 7-day unlock cache lives
 *         .build();
 * log.info(protection.notice());                   // one line: product, owner, masked key
 *
 * // Each validate: send protection.validateFields() with the request and give it the answer.
 * protection.accept(responseBody);                 // a valid answer carries "unlock"; a rejection forgets it
 *
 * byte[] core = protection.unseal(SEALED_CORE);    // throws Locked without a valid unlock
 * protection.integrity(MyPlugin.class.getClassLoader());  // OK / MODIFIED, sent with the next check
 * byte[] rules = protection.protectedFile("rules.dat");   // Standard plan
 * }</pre>
 *
 * <p><b>Core unlock.</b> {@code sunlicense seal} encrypts part of the product (its "core") under a key only
 * SunLicense holds. A valid license check answers with that key ({@code unlock}); a rejected one (suspended,
 * expired, revoked...) doesn't, and {@link #accept} then forgets the one it had. So a copy whose license check was
 * cut out can't run its core. To keep working through outages the unlock from the last valid check is cached on
 * disk for 7 days, encrypted with a key derived from the license key, the machine id and this machine, and an
 * offline license file ({@code .lic}) carries it too ({@link #acceptOffline}).
 *
 * <p><b>Tamper reports.</b> The sealed core can carry SHA-256 digests of the rest of the product (the classes of
 * the jar). {@link #integrity} compares them with what is running and remembers {@code OK} or {@code MODIFIED};
 * {@link #validateFields()} adds that to the next license check, where Sentinel sees it.
 *
 * <p>Honest limit: someone with a valid license can still extract the unlock and patch their copy; that copy then
 * fails its integrity check and is reported. Protection raises the cost and makes leaks visible.
 *
 * <p>This file needs nothing but the JDK (Java 11+). SunLicense's starter templates ship a copy of it, identical
 * apart from the package line: to update it, copy the SDK's file again rather than editing it.
 */
public final class SunLicenseProtection {
    public static final String DEFAULT_BASE_URL = "https://api.sunlicense.com";
    /** How long the unlock from the last valid check keeps working without an answer from SunLicense. */
    public static final Duration CACHE_TTL = Duration.ofDays(7);
    static final Duration SKEW = Duration.ofMinutes(10);
    static final String SEALED_PREFIX = "SLS1.";
    static final byte[] SEALED_AAD = "SLS1".getBytes(StandardCharsets.US_ASCII);
    static final String CACHE_PREFIX = "SLC1.";
    static final String CACHE_FILE = ".sunlicense-unlock-";
    static final int MAX_DETAIL = 200;
    static final Duration TIMEOUT = Duration.ofSeconds(15);
    private static final System.Logger LOG = System.getLogger("com.sunlicense.protection");
    private static final SecureRandom RANDOM = new SecureRandom();

    /** No unlock: the license wasn't confirmed valid (online, cached or offline), or the data was sealed for another product. */
    public static final class Locked extends Exception {
        private static final long serialVersionUID = 1L;

        public Locked(String message) {
            super(message);
        }
    }

    /** A protected file SunLicense refused (license not valid, file missing, plan without protected files). */
    public static final class Refused extends IOException {
        private static final long serialVersionUID = 1L;
        private final int status;

        public Refused(int status, String message) {
            super(message);
            this.status = status;
        }

        /** The HTTP status: 401/403 refused, 404 no such file, 402 plan without protected files. */
        public int status() {
            return status;
        }
    }

    /** One HTTP answer. */
    static final class Response {
        final int status;
        final byte[] body;

        Response(int status, byte[] body) {
            this.status = status;
            this.body = body;
        }
    }

    interface Transport {
        Response get(String url, Map<String, String> headers) throws IOException, InterruptedException;
    }

    private final String baseUrl;
    private final String apiKey;
    private final String productCode;
    private final String productName;
    private final String owner;
    private final String terms;
    private final Path cacheDirectory;
    private final Clock clock;
    private final Supplier<String> machine;
    private final Transport transport;

    private volatile String licenseKey;
    private volatile String fingerprint;
    private volatile byte[] unlock;
    private volatile Map<String, String> digests = Collections.emptyMap();
    private volatile String integrity;
    private volatile String integrityDetail;

    private SunLicenseProtection(Builder b) {
        this.baseUrl = b.baseUrl.replaceAll("/+$", "");
        this.apiKey = b.apiKey;
        this.productCode = b.productCode;
        this.productName = b.productName;
        this.owner = b.owner;
        this.terms = b.terms;
        this.cacheDirectory = b.cacheDirectory;
        this.clock = b.clock;
        this.machine = b.machine;
        this.transport = b.transport != null ? b.transport : new HttpTransport();
        this.licenseKey = trim(b.licenseKey);
        this.fingerprint = trim(b.fingerprint);
    }

    public static Builder builder() {
        return new Builder();
    }

    // ---- license and answers ----

    /** The license key and machine id this install checks with; a different key drops the unlock held in memory. */
    public void license(String licenseKey, String fingerprint) {
        String key = trim(licenseKey);
        if (key == null || !key.equals(this.licenseKey)) {
            unlock = null;
        }
        this.licenseKey = key;
        this.fingerprint = trim(fingerprint);
    }

    /**
     * Reads a license check's answer (the JSON body of {@code /api/v1/validate} or {@code /api/v2/license/validate}).
     * A valid answer with {@code unlock} keeps and caches it; a definite "no" ({@code "valid": false}) forgets it.
     * Anything unreadable is ignored (treat that like no answer).
     */
    public void accept(String responseBody) {
        Object parsed;
        try {
            parsed = Json.parse(responseBody);
        } catch (RuntimeException e) {
            return;
        }
        if (!(parsed instanceof Map)) {
            return;
        }
        Map<?, ?> body = (Map<?, ?>) parsed;
        Object valid = body.get("valid");
        if (Boolean.TRUE.equals(valid)) {
            Object u = body.get("unlock");
            accept(true, u instanceof String ? (String) u : null);
        } else if (Boolean.FALSE.equals(valid)) {
            accept(false, null);
        }
    }

    /** Same as {@link #accept(String)} for an answer already read: valid with its {@code unlock} (or null), or rejected. */
    public void accept(boolean valid, String unlockBase64) {
        if (!valid) {
            rejected();
            return;
        }
        if (unlockBase64 == null || unlockBase64.isBlank()) {
            return;   // valid, but the product has nothing sealed: keep what we have
        }
        byte[] key;
        try {
            key = Base64.getDecoder().decode(unlockBase64.trim());
        } catch (IllegalArgumentException e) {
            return;
        }
        if (key.length != 16 && key.length != 24 && key.length != 32) {
            return;
        }
        unlock = key;
        writeCache(key);
    }

    /** SunLicense said no: the unlock (in memory and on disk) is gone until the next valid check. */
    public void rejected() {
        unlock = null;
        Path file = cacheFile();
        if (file != null) {
            try {
                Files.deleteIfExists(file);
            } catch (IOException | RuntimeException e) {
                debug("Can't delete the unlock cache: " + e.getMessage());
            }
        }
    }

    /**
     * Takes the unlock from an offline license file ({@code .lic}): checks its signature with the organization's
     * public key, that it is for this license key and not expired or past its refresh window. Returns false (and
     * changes nothing) when the file isn't usable or carries no unlock.
     */
    public boolean acceptOffline(String file, String publicKeyBase64) {
        Map<?, ?> payload = verifiedOffline(file, publicKeyBase64);
        if (payload == null) {
            return false;
        }
        Object key = payload.get("licenseKey");
        if (licenseKey != null && key instanceof String && !licenseKey.equalsIgnoreCase(((String) key).trim())) {
            return false;
        }
        Instant now = clock.instant();
        Object issued = payload.get("issuedAt");
        if (issued instanceof String && instant((String) issued) != null && instant((String) issued).isAfter(now.plus(SKEW))) {
            return false;
        }
        Object policy = payload.get("policy");
        Object expires = policy instanceof Map ? ((Map<?, ?>) policy).get("expiresAt") : null;
        if (expires instanceof String && instant((String) expires) != null && !now.isBefore(instant((String) expires))) {
            return false;
        }
        Object refresh = payload.get("refreshAfter");
        if (refresh instanceof String && instant((String) refresh) != null && !now.isBefore(instant((String) refresh))) {
            return false;
        }
        Object u = payload.get("unlock");
        if (!(u instanceof String)) {
            return false;
        }
        try {
            byte[] k = Base64.getDecoder().decode(((String) u).trim());
            if (k.length != 16 && k.length != 24 && k.length != 32) {
                return false;
            }
            unlock = k;   // the file is its own cache: nothing written to disk
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /** True when an unlock is available: from this run's valid check, the offline file, or the cache (≤ 7 days). */
    public boolean unlocked() {
        return key() != null;
    }

    // ---- core unlock ----

    /**
     * Decrypts data sealed with {@code sunlicense seal} (an {@code SLS1.} string). Throws {@link Locked} without an
     * unlock, or when the data was sealed for another product. Remembers the digests sealed with it for
     * {@link #integrity}.
     */
    public byte[] unseal(String sealed) throws Locked {
        byte[] key = key();
        if (key == null) {
            throw new Locked("No valid license check yet: the protected part of this product stays locked.");
        }
        Opened opened;
        try {
            opened = open(sealed, key);
        } catch (GeneralSecurityException e) {
            throw new Locked("This data wasn't sealed for this product's unlock (sealed for another product, or re-sealed since).");
        } catch (IllegalArgumentException e) {
            throw new Locked("Not sealed data: " + e.getMessage());
        }
        digests = opened.digests;
        return opened.data;
    }

    /** {@link #unseal(String)} with the sealed text read from a stream (e.g. a resource in the jar). */
    public byte[] unseal(InputStream sealed) throws Locked, IOException {
        if (sealed == null) {
            throw new IOException("No sealed data (resource missing)");
        }
        try (InputStream in = sealed) {
            return unseal(new String(readAll(in), StandardCharsets.UTF_8));
        }
    }

    /** The digests sealed with the last data {@link #unseal} opened (path → lowercase hex SHA-256). */
    public Map<String, String> digests() {
        return digests;
    }

    static final class Opened {
        final byte[] data;
        final Map<String, String> digests;

        Opened(byte[] data, Map<String, String> digests) {
            this.data = data;
            this.digests = digests;
        }
    }

    /**
     * {@code SLS1.} + base64url(nonce 12 || AES-256-GCM ciphertext || tag 16), AAD {@code SLS1}; plaintext JSON
     * {@code {"v":1,"digests":{path: sha256 hex},"data":"<base64>"}} (spec 203, protection-test-vectors.json).
     */
    static Opened open(String sealed, byte[] key) throws GeneralSecurityException {
        if (sealed == null || !sealed.trim().startsWith(SEALED_PREFIX)) {
            throw new IllegalArgumentException("expected text starting with " + SEALED_PREFIX);
        }
        byte[] raw = decodeBase64(sealed.trim().substring(SEALED_PREFIX.length()));
        if (raw.length < 12 + 16) {
            throw new IllegalArgumentException("too short");
        }
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, raw, 0, 12));
        cipher.updateAAD(SEALED_AAD);
        byte[] plain = cipher.doFinal(raw, 12, raw.length - 12);
        Object parsed;
        try {
            parsed = Json.parse(new String(plain, StandardCharsets.UTF_8));
        } catch (RuntimeException e) {
            throw new IllegalArgumentException("sealed content isn't readable");
        }
        if (!(parsed instanceof Map) || !(((Map<?, ?>) parsed).get("data") instanceof String)) {
            throw new IllegalArgumentException("sealed content has no data");
        }
        Map<?, ?> m = (Map<?, ?>) parsed;
        byte[] data = decodeBase64((String) m.get("data"));
        Map<String, String> digests = new TreeMap<>();
        if (m.get("digests") instanceof Map) {
            for (Map.Entry<?, ?> e : ((Map<?, ?>) m.get("digests")).entrySet()) {
                if (e.getValue() instanceof String) {
                    digests.put(String.valueOf(e.getKey()), normalDigest((String) e.getValue()));
                }
            }
        }
        return new Opened(data, Collections.unmodifiableMap(digests));
    }

    /** Lowercase hex, without a {@code sha256:} prefix. */
    static String normalDigest(String digest) {
        String d = digest.trim().toLowerCase(java.util.Locale.ROOT);
        return d.startsWith("sha256:") ? d.substring(7) : d;
    }

    /**
     * A class loader over a sealed core that is a jar or zip (what the templates seal): its classes and resources,
     * with {@code parent} (the product's own class loader) for everything else.
     */
    public static ClassLoader classLoader(byte[] jar, ClassLoader parent) throws IOException {
        Map<String, byte[]> entries = new HashMap<>();
        try (ZipInputStream zip = new ZipInputStream(new ByteArrayInputStream(jar))) {
            ZipEntry e;
            while ((e = zip.getNextEntry()) != null) {
                if (!e.isDirectory()) {
                    entries.put(e.getName(), readAll(zip));
                }
            }
        }
        return new SealedClassLoader(entries, parent);
    }

    static final class SealedClassLoader extends ClassLoader {
        static {
            registerAsParallelCapable();
        }

        private final Map<String, byte[]> entries;

        SealedClassLoader(Map<String, byte[]> entries, ClassLoader parent) {
            super(parent);
            this.entries = entries;
        }

        @Override
        protected Class<?> findClass(String name) throws ClassNotFoundException {
            byte[] bytes = entries.get(name.replace('.', '/') + ".class");
            if (bytes == null) {
                throw new ClassNotFoundException(name);
            }
            return defineClass(name, bytes, 0, bytes.length);
        }

        @Override
        public InputStream getResourceAsStream(String name) {
            byte[] bytes = entries.get(name);
            return bytes != null ? new ByteArrayInputStream(bytes) : super.getResourceAsStream(name);
        }
    }

    // ---- tamper reports ----

    /**
     * Checks the classes and resources the sealed digests name, read through {@code loader} (the product's own class
     * loader reads them from its jar). Returns {@code "OK"} or {@code "MODIFIED"}, or null when nothing was sealed
     * with digests; the result goes with the next license check ({@link #validateFields()}).
     */
    public String integrity(ClassLoader loader) {
        return integrity(name -> {
            try (InputStream in = loader.getResourceAsStream(name)) {
                return in == null ? null : readAll(in);
            } catch (IOException e) {
                return null;
            }
        }, digests);
    }

    /** {@link #integrity(ClassLoader)} over a jar/zip file or a directory (e.g. the product's own jar). */
    public String integrity(Path jarOrDirectory) {
        if (Files.isDirectory(jarOrDirectory)) {
            return integrity(name -> {
                try {
                    Path p = jarOrDirectory.resolve(name).normalize();
                    return p.startsWith(jarOrDirectory) && Files.isRegularFile(p) ? Files.readAllBytes(p) : null;
                } catch (IOException | RuntimeException e) {
                    return null;
                }
            }, digests);
        }
        try (ZipFile zip = new ZipFile(jarOrDirectory.toFile())) {
            return integrity(name -> {
                ZipEntry e = zip.getEntry(name);
                if (e == null) {
                    return null;
                }
                try (InputStream in = zip.getInputStream(e)) {
                    return readAll(in);
                } catch (IOException ex) {
                    return null;
                }
            }, digests);
        } catch (IOException e) {
            return integrity(name -> null, digests);
        }
    }

    /** The jar (or directory) a class was loaded from, for {@link #integrity(Path)}; null when it can't be told. */
    public static Path codeSource(Class<?> anchor) {
        try {
            URL url = anchor.getProtectionDomain().getCodeSource().getLocation();
            return Paths.get(url.toURI());
        } catch (Exception e) {
            return null;
        }
    }

    /** Compares {@code digests} (path → hex SHA-256) with what {@code reader} returns for each path. */
    public String integrity(Function<String, byte[]> reader, Map<String, String> digests) {
        if (digests == null || digests.isEmpty()) {
            return null;
        }
        List<String> changed = new ArrayList<>();
        for (Map.Entry<String, String> d : new TreeMap<>(digests).entrySet()) {
            byte[] bytes = reader.apply(d.getKey());
            if (bytes == null || !hex(sha256(bytes)).equals(normalDigest(d.getValue()))) {
                changed.add(d.getKey() + (bytes == null ? " (missing)" : ""));
            }
        }
        if (changed.isEmpty()) {
            integrity = "OK";
            integrityDetail = null;
        } else {
            integrity = "MODIFIED";
            integrityDetail = detail(changed);
        }
        return integrity;
    }

    static String detail(List<String> changed) {
        StringBuilder b = new StringBuilder(changed.size() + " changed: ");
        int shown = 0;
        for (String c : changed) {
            String next = (shown == 0 ? "" : ", ") + c;
            int reserve = shown + 1 < changed.size() ? 16 : 0;   // room for ", +N more"
            if (b.length() + next.length() + reserve > MAX_DETAIL) {
                break;
            }
            b.append(next);
            shown++;
        }
        if (shown < changed.size()) {
            b.append(shown == 0 ? "" : ", ").append('+').append(changed.size() - shown).append(" more");
        }
        return b.length() > MAX_DETAIL ? b.substring(0, MAX_DETAIL) : b.toString();
    }

    /** The latest {@link #integrity} result, or null before any. */
    public String integrityResult() {
        return integrity;
    }

    /**
     * Fields to add to the next license check's JSON body: {@code integrity} and, when modified,
     * {@code integrityDetail}. Empty before any integrity check. Works as the official SDK's context map too.
     */
    public Map<String, String> validateFields() {
        Map<String, String> fields = new LinkedHashMap<>();
        String i = integrity;
        if (i != null) {
            fields.put("integrity", i);
            String d = integrityDetail;
            if (d != null) {
                fields.put("integrityDetail", d);
            }
        }
        return fields;
    }

    // ---- ownership notice ----

    /**
     * One line for the start-up log: product, owner, masked license key and terms link, e.g.
     * {@code "MyPlugin is licensed software by Example Studio. License AX8P-XXXX-XXXX-XXXX. Terms: https://…"}.
     * Never contains a full key or the buyer's name.
     */
    public String notice() {
        StringBuilder b = new StringBuilder(productName != null ? productName : "This product");
        b.append(" is licensed software");
        if (owner != null) {
            b.append(" by ").append(owner);
        }
        b.append(". License ").append(mask(licenseKey)).append('.');
        if (terms != null) {
            b.append(" Terms: ").append(terms);
        }
        return b.toString();
    }

    /** "AX8P-XXXX-XXXX-XXXX": the first group, the rest as X. */
    public static String mask(String key) {
        if (key == null || key.isBlank()) {
            return "(none)";
        }
        String[] groups = key.trim().split("-");
        StringBuilder out = new StringBuilder();
        if (groups.length == 1) {
            String k = groups[0];
            out.append(k, 0, Math.min(4, k.length()));
            for (int i = 4; i < k.length(); i++) {
                out.append('X');
            }
            return out.toString();
        }
        out.append(groups[0]);
        for (int i = 1; i < groups.length; i++) {
            out.append('-');
            for (int j = 0; j < groups[i].length(); j++) {
                out.append('X');
            }
        }
        return out.toString();
    }

    // ---- protected files ----

    /**
     * Downloads a protected file uploaded to the product (Standard plan). SunLicense sends it only while the license
     * is valid. Throws {@link Refused} when it says no, {@link IOException} when it can't be reached.
     */
    public byte[] protectedFile(String name) throws IOException {
        if (productCode == null || productCode.isBlank()) {
            throw new IllegalStateException("Set productCode(...) to download protected files");
        }
        if (licenseKey == null) {
            throw new Refused(401, "No license key");
        }
        String url = baseUrl + "/api/v2/protected-files/" + segment(productCode) + "/" + segment(name);
        Map<String, String> headers = new LinkedHashMap<>();
        if (apiKey != null && !apiKey.isBlank()) {
            headers.put("Authorization", "Bearer " + apiKey);
        }
        headers.put("X-License-Key", licenseKey);
        if (fingerprint != null) {
            headers.put("X-Fingerprint", fingerprint);
        }
        Response r;
        try {
            r = transport.get(url, headers);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted", e);
        }
        if (r.status == 200) {
            return r.body;
        }
        if (r.status >= 500 || r.status == 429) {
            throw new IOException("SunLicense returned HTTP " + r.status + " for protected file " + name);
        }
        String code = null;
        try {
            Object body = Json.parse(new String(r.body, StandardCharsets.UTF_8));
            if (body instanceof Map) {
                Object c = ((Map<?, ?>) body).get("code");
                Object d = ((Map<?, ?>) body).get("detail");
                code = c instanceof String ? (String) c : d instanceof String ? (String) d : null;
            }
        } catch (RuntimeException e) {
            // keep the status only
        }
        throw new Refused(r.status, "SunLicense refused protected file " + name + " (HTTP " + r.status
                + (code != null ? ", " + code : "") + ")");
    }

    private static String segment(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    // ---- the unlock cache: one file per license key, AES-GCM under a key bound to the key, the machine id and this machine ----

    private byte[] key() {
        byte[] k = unlock;
        if (k != null) {
            return k;
        }
        k = readCache();
        if (k != null) {
            unlock = k;
        }
        return k;
    }

    Path cacheFile() {
        if (cacheDirectory == null || licenseKey == null) {
            return null;
        }
        String id = hex(sha256(("sunlicense-unlock-file\0" + licenseKey).getBytes(StandardCharsets.UTF_8))).substring(0, 16);
        return cacheDirectory.resolve(CACHE_FILE + id);
    }

    private byte[] cacheKey() {
        String binding = "sunlicense-unlock-cache\0" + licenseKey + "\0" + (fingerprint == null ? "" : fingerprint) + "\0" + machine.get();
        return sha256(binding.getBytes(StandardCharsets.UTF_8));
    }

    private void writeCache(byte[] key) {
        Path file = cacheFile();
        if (file == null) {
            return;
        }
        try {
            byte[] plain = (clock.millis() + "\n" + Base64.getEncoder().encodeToString(key)).getBytes(StandardCharsets.UTF_8);
            byte[] nonce = new byte[12];
            RANDOM.nextBytes(nonce);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cacheKey(), "AES"), new GCMParameterSpec(128, nonce));
            byte[] ct = cipher.doFinal(plain);
            byte[] out = new byte[nonce.length + ct.length];
            System.arraycopy(nonce, 0, out, 0, nonce.length);
            System.arraycopy(ct, 0, out, nonce.length, ct.length);
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            Files.write(tmp, (CACHE_PREFIX + Base64.getUrlEncoder().withoutPadding().encodeToString(out)).getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            debug("Can't write the unlock cache: " + e.getMessage());
        }
    }

    private byte[] readCache() {
        Path file = cacheFile();
        if (file == null || !Files.isRegularFile(file)) {
            return null;
        }
        try {
            String text = new String(Files.readAllBytes(file), StandardCharsets.UTF_8).trim();
            if (!text.startsWith(CACHE_PREFIX)) {
                return null;
            }
            byte[] raw = decodeBase64(text.substring(CACHE_PREFIX.length()));
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cacheKey(), "AES"), new GCMParameterSpec(128, raw, 0, 12));
            String plain = new String(cipher.doFinal(raw, 12, raw.length - 12), StandardCharsets.UTF_8);
            int nl = plain.indexOf('\n');
            Instant saved = Instant.ofEpochMilli(Long.parseLong(plain.substring(0, nl)));
            Instant now = clock.instant();
            if (saved.isAfter(now.plus(SKEW)) || !now.isBefore(saved.plus(CACHE_TTL))) {
                return null;   // older than 7 days, or the clock was turned back
            }
            return Base64.getDecoder().decode(plain.substring(nl + 1));
        } catch (IOException | GeneralSecurityException | RuntimeException e) {
            return null;   // another machine, another license key, or a damaged file
        }
    }

    /** SHA-256 of the OS, architecture, host name and hardware addresses: what makes a copied cache file useless elsewhere. */
    static String machineId() {
        StringBuilder raw = new StringBuilder(String.valueOf(System.getProperty("os.name"))).append('|')
                .append(System.getProperty("os.arch"));
        try {
            raw.append('|').append(InetAddress.getLocalHost().getHostName());
        } catch (IOException | RuntimeException e) {
            raw.append("|?");
        }
        try {
            TreeSet<String> macs = new TreeSet<>();
            for (NetworkInterface ni : Collections.list(NetworkInterface.getNetworkInterfaces())) {
                byte[] mac = ni.getHardwareAddress();
                if (mac != null && !ni.isVirtual() && !ni.isLoopback()) {
                    macs.add(hex(mac));
                }
            }
            raw.append('|').append(String.join(",", macs));
        } catch (IOException | RuntimeException e) {
            raw.append("|?");
        }
        return hex(sha256(raw.toString().getBytes(StandardCharsets.UTF_8)));
    }

    // ---- offline license files ----

    private static Map<?, ?> verifiedOffline(String file, String publicKeyBase64) {
        if (file == null || publicKeyBase64 == null || publicKeyBase64.isBlank()) {
            return null;
        }
        String[] parts = file.trim().split("\\.");
        if (parts.length != 2) {
            return null;
        }
        try {
            byte[] payload = Base64.getUrlDecoder().decode(parts[0]);
            PublicKey key = KeyFactory.getInstance("Ed25519")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64.trim())));
            Signature verifier = Signature.getInstance("Ed25519");
            verifier.initVerify(key);
            verifier.update(payload);
            if (!verifier.verify(Base64.getUrlDecoder().decode(parts[1]))) {
                return null;
            }
            Object parsed = Json.parse(new String(payload, StandardCharsets.UTF_8));
            return parsed instanceof Map ? (Map<?, ?>) parsed : null;
        } catch (IllegalArgumentException | GeneralSecurityException e) {
            return null;
        }
    }

    private static Instant instant(String s) {
        try {
            return Instant.parse(s.trim());
        } catch (RuntimeException e) {
            return null;
        }
    }

    // ---- helpers ----

    /** Base64 in any flavour the server may send: url-safe or standard, with or without padding. */
    static byte[] decodeBase64(String s) {
        String t = s.trim().replace('-', '+').replace('_', '/').replace("=", "");
        int pad = (4 - t.length() % 4) % 4;
        StringBuilder b = new StringBuilder(t);
        for (int i = 0; i < pad; i++) {
            b.append('=');
        }
        return Base64.getDecoder().decode(b.toString());
    }

    static byte[] sha256(byte[] bytes) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(bytes);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    static String hex(byte[] bytes) {
        StringBuilder b = new StringBuilder(bytes.length * 2);
        for (byte x : bytes) {
            b.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return b.toString();
    }

    static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) > 0) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }

    private static String trim(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }

    private static void debug(String message) {
        LOG.log(System.Logger.Level.DEBUG, message);
    }

    /** A small JSON reader (objects → Map, arrays → List, numbers → Double/Long, strings, booleans, null). */
    static final class Json {
        private final String s;
        private int i;

        private Json(String s) {
            this.s = s;
        }

        static Object parse(String text) {
            if (text == null) {
                throw new IllegalArgumentException("no JSON");
            }
            Json j = new Json(text);
            j.ws();
            Object v = j.value();
            j.ws();
            if (j.i != text.length()) {
                throw new IllegalArgumentException("trailing characters");
            }
            return v;
        }

        private Object value() {
            if (i >= s.length()) {
                throw new IllegalArgumentException("unexpected end");
            }
            char c = s.charAt(i);
            if (c == '{') {
                return object();
            }
            if (c == '[') {
                return array();
            }
            if (c == '"') {
                return string();
            }
            if (s.startsWith("true", i)) {
                i += 4;
                return Boolean.TRUE;
            }
            if (s.startsWith("false", i)) {
                i += 5;
                return Boolean.FALSE;
            }
            if (s.startsWith("null", i)) {
                i += 4;
                return null;
            }
            return number();
        }

        private Map<String, Object> object() {
            Map<String, Object> m = new LinkedHashMap<>();
            i++;
            ws();
            if (peek() == '}') {
                i++;
                return m;
            }
            while (true) {
                ws();
                String k = string();
                ws();
                expect(':');
                ws();
                m.put(k, value());
                ws();
                if (peek() == ',') {
                    i++;
                    continue;
                }
                expect('}');
                return m;
            }
        }

        private List<Object> array() {
            List<Object> l = new ArrayList<>();
            i++;
            ws();
            if (peek() == ']') {
                i++;
                return l;
            }
            while (true) {
                ws();
                l.add(value());
                ws();
                if (peek() == ',') {
                    i++;
                    continue;
                }
                expect(']');
                return l;
            }
        }

        private String string() {
            expect('"');
            StringBuilder b = new StringBuilder();
            while (true) {
                if (i >= s.length()) {
                    throw new IllegalArgumentException("unterminated string");
                }
                char c = s.charAt(i++);
                if (c == '"') {
                    return b.toString();
                }
                if (c != '\\') {
                    b.append(c);
                    continue;
                }
                char e = s.charAt(i++);
                switch (e) {
                    case 'n': b.append('\n'); break;
                    case 't': b.append('\t'); break;
                    case 'r': b.append('\r'); break;
                    case 'b': b.append('\b'); break;
                    case 'f': b.append('\f'); break;
                    case 'u':
                        b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                        i += 4;
                        break;
                    default: b.append(e);
                }
            }
        }

        private Object number() {
            int start = i;
            while (i < s.length() && "+-0123456789.eE".indexOf(s.charAt(i)) >= 0) {
                i++;
            }
            String n = s.substring(start, i);
            if (n.isEmpty()) {
                throw new IllegalArgumentException("unexpected character at " + start);
            }
            return n.contains(".") || n.contains("e") || n.contains("E") ? (Object) Double.valueOf(n) : (Object) Long.valueOf(n);
        }

        private char peek() {
            if (i >= s.length()) {
                throw new IllegalArgumentException("unexpected end");
            }
            return s.charAt(i);
        }

        private void expect(char c) {
            if (peek() != c) {
                throw new IllegalArgumentException("expected '" + c + "' at " + i);
            }
            i++;
        }

        private void ws() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
                i++;
            }
        }
    }

    private static final class HttpTransport implements Transport {
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();

        @Override
        public Response get(String url, Map<String, String> headers) throws IOException, InterruptedException {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT).GET();
            for (Map.Entry<String, String> h : headers.entrySet()) {
                request.header(h.getKey(), h.getValue());
            }
            HttpResponse<byte[]> res = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            return new Response(res.statusCode(), res.body());
        }
    }

    /** Settings; only {@link #licenseKey} is needed for unlock, {@link #productCode} too for protected files. */
    public static final class Builder {
        private String baseUrl = DEFAULT_BASE_URL;
        private String apiKey;
        private String licenseKey;
        private String fingerprint;
        private String productCode;
        private String productName;
        private String owner;
        private String terms;
        private Path cacheDirectory = Paths.get(System.getProperty("user.home", "."), ".sunlicense");
        private Clock clock = Clock.systemUTC();
        private Supplier<String> machine = SunLicenseProtection::machineId;
        private Transport transport;

        private Builder() {
        }

        public Builder baseUrl(String baseUrl) {
            if (baseUrl != null && !baseUrl.isBlank()) {
                this.baseUrl = baseUrl.trim();
            }
            return this;
        }

        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        public Builder licenseKey(String licenseKey) {
            this.licenseKey = licenseKey;
            return this;
        }

        public Builder fingerprint(String fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        /** The product's code in SunLicense, for {@link SunLicenseProtection#protectedFile}. */
        public Builder productCode(String productCode) {
            this.productCode = productCode;
            return this;
        }

        /** Product and owner (seller) names for {@link SunLicenseProtection#notice()}. */
        public Builder product(String productName, String owner) {
            this.productName = trim(productName);
            this.owner = trim(owner);
            return this;
        }

        /** The terms link {@link SunLicenseProtection#notice()} ends with. */
        public Builder terms(String termsUrl) {
            this.terms = trim(termsUrl);
            return this;
        }

        /** Where the unlock cache is kept (the product's data folder); null = memory only. Default {@code ~/.sunlicense}. */
        public Builder cacheDirectory(Path cacheDirectory) {
            this.cacheDirectory = cacheDirectory;
            return this;
        }

        Builder clock(Clock clock) {
            this.clock = clock;
            return this;
        }

        Builder machine(Supplier<String> machine) {
            this.machine = machine;
            return this;
        }

        Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        public SunLicenseProtection build() {
            return new SunLicenseProtection(this);
        }
    }
}
