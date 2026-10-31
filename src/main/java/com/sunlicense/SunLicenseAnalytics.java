package com.sunlicense;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.regex.Pattern;

/**
 * Built-in product analytics (spec 185 §4): every 30 minutes, on a background thread, this install tells
 * SunLicense its product version, OS, architecture, CPU cores, locale, Java version and platform (Paper,
 * Velocity, Fabric, Forge, a Discord bot or standalone, with the server software's version). Sellers see the
 * totals on the product's Analytics tab.
 *
 * <pre>{@code
 * // A licensed product: the same API key, license key and machine id it validates with.
 * SunLicenseAnalytics analytics = SunLicenseAnalytics.builder()
 *         .apiKey(apiKey).licenseKey(licenseKey).fingerprint(machineId)
 *         .productVersion("2.3.1")
 *         .enabled(config.getBoolean("analytics", true))
 *         .start();
 * // A free product: its public product analytics id (Product → Analytics), no license needed.
 * SunLicenseAnalytics analytics = SunLicenseAnalytics.builder()
 *         .productAnalyticsId("pa_7Hk2mQ9xZr4LbN8vT1wYcD").dataDirectory(dataFolder).start();
 * // On shutdown or plugin disable:
 * analytics.close();
 * }</pre>
 *
 * <p>It never blocks, delays or fails a license check and never throws: errors are swallowed (one debug log
 * line when the outcome changes). Nothing is sent while the product's config switch is off, while the
 * environment variable {@code SUNLICENSE_ANALYTICS} is {@code off}/{@code false}/{@code 0}, or while the
 * system property {@code sunlicense.analytics} is {@code false}; each is checked before every report. No
 * personal data is sent: no user names, host names, IP addresses, file paths or player names.
 *
 * <p>This file needs nothing but the JDK (Java 11+). SunLicense's starter templates ship a copy of the Java
 * SDK's {@code SunLicenseAnalytics}, identical apart from the package line: to update it, copy the SDK's file
 * again rather than editing it.
 */
public final class SunLicenseAnalytics implements AutoCloseable {
    /** Sent as {@code sdk.name}/{@code sdk.version}; bump the version with each SDK release. */
    public static final String SDK_NAME = "java";
    public static final String SDK_VERSION = "0.1.0";
    public static final String DEFAULT_BASE_URL = "https://api.sunlicense.com";
    /** Environment variable and system property that switch analytics off on a machine. */
    public static final String ENV_SWITCH = "SUNLICENSE_ANALYTICS";
    public static final String PROPERTY_SWITCH = "sunlicense.analytics";

    static final String PATH = "/api/v2/analytics/report";
    static final Duration INTERVAL = Duration.ofMinutes(30);
    static final Duration MIN_WAIT = Duration.ofMinutes(1);
    static final Duration MAX_WAIT = Duration.ofHours(24);
    static final Duration TIMEOUT = Duration.ofSeconds(10);
    static final int MAX_BODY = 16 * 1024;
    static final String INSTALL_ID_FILE = ".sunlicense-install-id";
    /** Report keys every report keeps; anything else (feature usage, custom charts) goes first when a report is too big. */
    static final Set<String> CORE_KEYS = new HashSet<>(Arrays.asList(
            "schema", "licenseKey", "fingerprint", "productAnalyticsId", "installId", "sdk", "metrics"));
    private static final Pattern INSTALL_ID = Pattern.compile("[A-Za-z0-9_-]{8,64}");
    private static final Set<String> OFF = new HashSet<>(Arrays.asList("off", "false", "0", "no", "disabled"));
    private static final System.Logger LOG = System.getLogger("com.sunlicense.analytics");

    /** Something that adds to each report (feature usage and custom charts, #188) and hears whether it was taken. */
    interface Section {
        void write(Map<String, Object> report);

        default void sent(boolean accepted) {
        }
    }

    /** One HTTP answer: status (-1 = no answer) and its Retry-After header. */
    static final class Answer {
        final int status;
        final String retryAfter;

        Answer(int status, String retryAfter) {
            this.status = status;
            this.retryAfter = retryAfter;
        }
    }

    interface Transport {
        Answer post(String url, Map<String, String> headers, byte[] body) throws IOException, InterruptedException;
    }

    /** What platform the product runs on, from the classes the JVM can see. */
    static final class Platform {
        final String name;
        final String version;

        Platform(String name, String version) {
            this.name = name;
            this.version = version;
        }
    }

    private final String endpoint;
    private final String apiKey;
    private final Supplier<String> licenseKey;
    private final String fingerprint;
    private final String productAnalyticsId;
    private final Path installIdFile;
    private final Supplier<String> productVersion;
    private final Platform platformOverride;
    private final BooleanSupplier enabled;
    private final Function<String, String> env;
    private final Function<String, String> props;
    private final Transport transport;
    private final Random random;
    private final Duration firstDelay;
    private final List<Section> sections = new CopyOnWriteArrayList<>();

    private volatile boolean closed;
    private ScheduledExecutorService scheduler;
    private Map<String, Object> systemMetrics;
    private String installId;
    private String lastOutcome;

    private SunLicenseAnalytics(Builder b) {
        this.endpoint = b.baseUrl.replaceAll("/+$", "") + PATH;
        this.apiKey = clean(b.apiKey, 512);
        this.licenseKey = b.licenseKey;
        this.fingerprint = clean(b.fingerprint, 255);
        this.productAnalyticsId = clean(b.productAnalyticsId, 64);
        this.installIdFile = b.installIdFile;
        this.productVersion = b.productVersion;
        this.platformOverride = b.platformName == null ? null : new Platform(b.platformName, b.platformVersion);
        this.enabled = b.enabled;
        this.env = b.env;
        this.props = b.props;
        this.transport = b.transport != null ? b.transport : new HttpTransport();
        this.random = b.random;
        this.firstDelay = b.firstDelay;
    }

    public static Builder builder() {
        return new Builder();
    }

    /** A free product: reports with its public product analytics id (Product → Analytics in the dashboard). */
    public static SunLicenseAnalytics forProduct(String productAnalyticsId) {
        return builder().productAnalyticsId(productAnalyticsId).start();
    }

    /** True unless the product's switch, {@code SUNLICENSE_ANALYTICS} or {@code -Dsunlicense.analytics} turns it off. */
    public boolean isEnabled() {
        return !optedOut();
    }

    /** Stops reporting. Call it when the product shuts down (a plugin's onDisable), so the thread goes too. */
    @Override
    public void close() {
        closed = true;
        ScheduledExecutorService s = scheduler;
        if (s != null) {
            s.shutdownNow();
        }
    }

    /**
     * Sends one report now, on the caller's thread, and returns the HTTP status (204 = stored, 0 = nothing sent
     * because analytics is off or the product isn't identified, -1 = no answer). For tests and the CLI; a
     * product leaves it to the schedule.
     */
    public int sendNow() {
        return send().status;
    }

    void add(Section section) {
        sections.add(section);
    }

    private SunLicenseAnalytics begin() {
        if (productAnalyticsId == null && (apiKey == null || fingerprint == null)) {
            outcome("no-identity", "no product analytics id, and no API key and machine id: not reporting");
            return this;
        }
        try {
            scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "SunLicense analytics");
                t.setDaemon(true);
                t.setPriority(Thread.MIN_PRIORITY);
                return t;
            });
            schedule(firstDelay != null ? firstDelay : firstDelay(random));
        } catch (RuntimeException e) {
            outcome("no-thread", "can't start the analytics thread: " + e);
        }
        return this;
    }

    /** First report after a random 1–30 minutes, so a fleet restarted together doesn't report together. */
    static Duration firstDelay(Random random) {
        return Duration.ofSeconds(60 + random.nextInt(29 * 60 + 1));
    }

    private void schedule(Duration delay) {
        ScheduledExecutorService s = scheduler;
        if (closed || s == null) {
            return;
        }
        try {
            s.schedule(this::tick, delay.toMillis(), TimeUnit.MILLISECONDS);
        } catch (RejectedExecutionException e) {
            // closed meanwhile
        }
    }

    private void tick() {
        Duration next = INTERVAL;
        try {
            Answer a = send();
            next = nextDelay(a.status, a.retryAfter);
        } catch (Throwable t) {
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            outcome("error", "report failed: " + t);
        } finally {
            schedule(next);
        }
    }

    /** 30 minutes after a 204 or no answer; else the server's Retry-After, between 1 minute and 24 hours. */
    static Duration nextDelay(int status, String retryAfter) {
        if (status == 204 || retryAfter == null) {
            return INTERVAL;
        }
        long seconds;
        try {
            seconds = Long.parseLong(retryAfter.trim());
        } catch (NumberFormatException e) {
            return INTERVAL;   // an HTTP date: not something our server sends
        }
        Duration d = Duration.ofSeconds(Math.max(0, seconds));
        return d.compareTo(MIN_WAIT) < 0 ? MIN_WAIT : d.compareTo(MAX_WAIT) > 0 ? MAX_WAIT : d;
    }

    private Answer send() {
        if (closed) {
            return new Answer(0, null);
        }
        if (optedOut()) {
            outcome("off", "analytics is switched off; nothing sent");
            return new Answer(0, null);
        }
        Map<String, Object> report = report();
        if (report == null) {
            outcome("no-identity", "no license key yet and no product analytics id; nothing sent");
            return new Answer(0, null);
        }
        byte[] body = json(report).getBytes(StandardCharsets.UTF_8);
        if (body.length > MAX_BODY) {
            report.keySet().retainAll(CORE_KEYS);
            body = json(report).getBytes(StandardCharsets.UTF_8);
        }
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("Content-Type", "application/json");
        headers.put("User-Agent", "sunlicense-" + SDK_NAME + "/" + SDK_VERSION + " analytics");
        if (report.containsKey("licenseKey")) {
            headers.put("Authorization", "Bearer " + apiKey);
        }
        Answer answer;
        try {
            answer = transport.post(endpoint, headers, body);
        } catch (IOException | RuntimeException e) {
            answer = new Answer(-1, null);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            answer = new Answer(-1, null);
        }
        boolean accepted = answer.status == 204;
        for (Section s : sections) {
            try {
                s.sent(accepted);
            } catch (RuntimeException e) {
                // a section's bookkeeping never stops reporting
            }
        }
        if (accepted) {
            outcome("204", "report accepted");
        } else if (answer.status < 0) {
            outcome("no-answer", "SunLicense didn't answer; next report in 30 minutes");
        } else {
            outcome("http-" + answer.status, "report answered HTTP " + answer.status + "; next in "
                    + nextDelay(answer.status, answer.retryAfter).getSeconds() + " s");
        }
        return answer;
    }

    private boolean optedOut() {
        if (isOff(env.apply(ENV_SWITCH)) || isOff(props.apply(PROPERTY_SWITCH))) {
            return true;
        }
        try {
            return !enabled.getAsBoolean();
        } catch (RuntimeException e) {
            return true;   // a config that can't be read counts as off
        }
    }

    static boolean isOff(String value) {
        return value != null && OFF.contains(value.trim().toLowerCase(Locale.ROOT));
    }

    /** The report body (§4.2), or null when this install can't say who it is yet. */
    Map<String, Object> report() {
        String key = clean(get(licenseKey), 128);
        boolean licensed = key != null && apiKey != null && fingerprint != null;
        if (!licensed && productAnalyticsId == null) {
            return null;
        }
        Map<String, Object> r = new LinkedHashMap<>();
        r.put("schema", 1);
        if (licensed) {
            r.put("licenseKey", key);
            r.put("fingerprint", fingerprint);
        }
        if (productAnalyticsId != null) {
            r.put("productAnalyticsId", productAnalyticsId);
            r.put("installId", installId());   // also with a license: an unknown key then still counts (§4.1)
        }
        Map<String, Object> sdk = new LinkedHashMap<>();
        sdk.put("name", SDK_NAME);
        sdk.put("version", SDK_VERSION);
        r.put("sdk", sdk);
        Map<String, Object> metrics = new LinkedHashMap<>();
        put(metrics, "productVersion", clean(get(productVersion), 64));
        metrics.putAll(systemMetrics());
        r.put("metrics", metrics);
        for (Section s : sections) {
            try {
                s.write(r);
            } catch (RuntimeException e) {
                // a broken section is left out, the built-in metrics still go
            }
        }
        return r;
    }

    private synchronized Map<String, Object> systemMetrics() {
        if (systemMetrics == null) {
            systemMetrics = collect(props, platformOverride != null ? platformOverride : detectPlatform());
        }
        return systemMetrics;
    }

    /** Raw values; the server maps them to families and majors (§4.4). */
    static Map<String, Object> collect(Function<String, String> props, Platform platform) {
        Map<String, Object> m = new LinkedHashMap<>();
        put(m, "os", clean(props.apply("os.name"), 64));
        put(m, "osVersion", clean(props.apply("os.version"), 64));
        put(m, "arch", clean(props.apply("os.arch"), 64));
        m.put("cores", Math.max(1, Math.min(1024, Runtime.getRuntime().availableProcessors())));
        put(m, "locale", clean(Locale.getDefault().toString(), 64));
        m.put("runtime", "java");
        put(m, "runtimeVersion", clean(props.apply("java.version"), 64));
        if (platform != null) {
            put(m, "platform", clean(platform.name == null ? null : platform.name.toLowerCase(Locale.ROOT), 32));
            put(m, "platformVersion", clean(platform.version, 64));
        }
        return m;
    }

    private synchronized String installId() {
        if (installId != null) {
            return installId;
        }
        try {
            if (Files.isRegularFile(installIdFile)) {
                String stored = new String(Files.readAllBytes(installIdFile), StandardCharsets.UTF_8).trim();
                if (INSTALL_ID.matcher(stored).matches()) {
                    return installId = stored;
                }
            }
        } catch (IOException | RuntimeException e) {
            // unreadable: make a new one
        }
        installId = UUID.randomUUID().toString();
        try {
            Path dir = installIdFile.toAbsolutePath().getParent();
            if (dir != null) {
                Files.createDirectories(dir);
            }
            Files.write(installIdFile, installId.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException e) {
            // read-only disk: this run still has an id, the next start makes another
        }
        return installId;
    }

    private void outcome(String kind, String message) {
        if (!kind.equals(lastOutcome)) {
            lastOutcome = kind;
            LOG.log(System.Logger.Level.DEBUG, "SunLicense analytics: " + message);
        }
    }

    // ---- platform detection, by class presence and reflection: no compile-time dependency on any platform ----

    static Platform detectPlatform() {
        try {
            return platform();
        } catch (Throwable t) {
            if (t instanceof VirtualMachineError) {
                throw (VirtualMachineError) t;
            }
            return new Platform("standalone", null);
        }
    }

    private static Platform platform() {
        if (present("org.bukkit.Bukkit")) {   // Bukkit, Spigot, Paper, Purpur, Folia, hybrids: the server says its name
            String name = str(callStatic("org.bukkit.Bukkit", "getName"));
            if (name == null) {
                name = present("io.papermc.paper.threadedregions.RegionizedServer") ? "folia"
                        : present("com.destroystokyo.paper.PaperConfig") || present("io.papermc.paper.configuration.Configuration") ? "paper"
                        : present("org.spigotmc.SpigotConfig") ? "spigot" : "bukkit";
            }
            return new Platform(name, str(callStatic("org.bukkit.Bukkit", "getBukkitVersion")));
        }
        if (present("net.md_5.bungee.api.ProxyServer")) {   // BungeeCord, Waterfall
            Object proxy = callStatic("net.md_5.bungee.api.ProxyServer", "getInstance");
            String name = str(call(proxy, "getName"));
            return new Platform(name == null ? "bungeecord" : name, bungeeVersion(str(call(proxy, "getVersion"))));
        }
        if (present("com.velocitypowered.api.proxy.ProxyServer")) {
            return new Platform("velocity", implementationVersion("com.velocitypowered.proxy.VelocityServer",
                    "com.velocitypowered.api.proxy.ProxyServer"));
        }
        if (present("org.spongepowered.api.Sponge")) {
            Object p = first(callStatic("org.spongepowered.api.Sponge", "platform"), callStatic("org.spongepowered.api.Sponge", "getPlatform"));
            Object mc = first(call(p, "minecraftVersion"), call(p, "getMinecraftVersion"));
            return new Platform("sponge", str(first(call(mc, "name"), call(mc, "getName"))));
        }
        if (present("net.neoforged.fml.loading.FMLLoader")) {
            return new Platform("neoforge", str(first(fmlMinecraftVersion("net.neoforged.fml.loading.FMLLoader"),
                    callStatic("net.neoforged.neoforge.internal.versions.neoform.NeoFormVersion", "getMCVersion"))));
        }
        if (present("net.minecraftforge.fml.loading.FMLLoader")) {
            return new Platform("forge", str(first(callStatic("net.minecraftforge.versions.mcp.MCPVersion", "getMCVersion"),
                    fmlMinecraftVersion("net.minecraftforge.fml.loading.FMLLoader"))));
        }
        if (present("org.quiltmc.loader.api.QuiltLoader")) {   // before Fabric: Quilt also has Fabric's loader API
            return new Platform("quilt", fabricMinecraftVersion());
        }
        if (present("net.fabricmc.loader.api.FabricLoader")) {
            return new Platform("fabric", fabricMinecraftVersion());
        }
        if (present("net.dv8tion.jda.api.JDA")) {
            return new Platform("discord", str(staticField("net.dv8tion.jda.api.JDAInfo", "VERSION")));
        }
        if (present("org.javacord.api.Javacord")) {
            return new Platform("discord", str(staticField("org.javacord.api.Javacord", "VERSION")));
        }
        return new Platform("standalone", null);
    }

    private static String fabricMinecraftVersion() {
        Object loader = callStatic("net.fabricmc.loader.api.FabricLoader", "getInstance");
        Object found = call(loader, "getModContainer", "minecraft");
        Object container = found instanceof Optional ? ((Optional<?>) found).orElse(null) : null;
        return str(call(call(call(container, "getMetadata"), "getVersion"), "getFriendlyString"));
    }

    private static Object fmlMinecraftVersion(String loader) {
        Object info = first(callStatic(loader, "versionInfo"), call(callStatic(loader, "getCurrent"), "getVersionInfo"));
        return call(info, "mcVersion");
    }

    /** {@code git:BungeeCord-Bootstrap:1.21-R0.1-SNAPSHOT:fd8eb79:1893} → {@code 1.21-R0.1-SNAPSHOT}. */
    static String bungeeVersion(String version) {
        if (version == null) {
            return null;
        }
        for (String part : version.split(":")) {
            if (!part.isEmpty() && Character.isDigit(part.charAt(0))) {
                return part;
            }
        }
        return version;
    }

    private static String implementationVersion(String... classNames) {
        for (String name : classNames) {
            Class<?> c = find(name);
            Package p = c == null ? null : c.getPackage();
            if (p != null && p.getImplementationVersion() != null) {
                return p.getImplementationVersion();
            }
        }
        return null;
    }

    static boolean present(String className) {
        return find(className) != null;
    }

    private static Class<?> find(String className) {
        List<ClassLoader> loaders = new ArrayList<>();
        loaders.add(SunLicenseAnalytics.class.getClassLoader());
        ClassLoader context = Thread.currentThread().getContextClassLoader();
        if (context != null && !loaders.contains(context)) {
            loaders.add(context);
        }
        for (ClassLoader loader : loaders) {
            try {
                return Class.forName(className, false, loader);
            } catch (ClassNotFoundException | LinkageError e) {
                // not here
            }
        }
        return null;
    }

    private static Object callStatic(String className, String method) {
        Class<?> c = find(className);
        if (c == null) {
            return null;
        }
        try {
            Method m = c.getMethod(method);
            return Modifier.isStatic(m.getModifiers()) ? m.invoke(null) : null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return null;
        }
    }

    private static Object staticField(String className, String field) {
        Class<?> c = find(className);
        if (c == null) {
            return null;
        }
        try {
            Field f = c.getField(field);
            return Modifier.isStatic(f.getModifiers()) ? f.get(null) : null;
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return null;
        }
    }

    /** Calls a public no-arg (or one String arg) method through a public type, so non-public implementations work. */
    private static Object call(Object target, String method, String... args) {
        if (target == null) {
            return null;
        }
        Class<?>[] types = new Class<?>[args.length];
        Arrays.fill(types, String.class);
        Method m = publicMethod(target.getClass(), method, types);
        if (m == null) {
            return null;
        }
        try {
            return m.invoke(target, (Object[]) args);
        } catch (ReflectiveOperationException | RuntimeException | LinkageError e) {
            return null;
        }
    }

    private static Method publicMethod(Class<?> c, String name, Class<?>[] types) {
        if (c == null) {
            return null;
        }
        if (Modifier.isPublic(c.getModifiers())) {
            try {
                Method m = c.getMethod(name, types);
                if (Modifier.isPublic(m.getDeclaringClass().getModifiers())) {
                    return m;
                }
            } catch (NoSuchMethodException e) {
                // look further up
            }
        }
        for (Class<?> i : c.getInterfaces()) {
            Method m = publicMethod(i, name, types);
            if (m != null) {
                return m;
            }
        }
        return publicMethod(c.getSuperclass(), name, types);
    }

    private static Object first(Object a, Object b) {
        return a != null ? a : b;
    }

    private static String str(Object o) {
        return o == null ? null : o.toString();
    }

    // ---- values and JSON (no JSON library, so the file can be copied anywhere) ----

    /** Trimmed, control characters removed, cut at {@code max}; null when empty. */
    static String clean(String s, int max) {
        if (s == null) {
            return null;
        }
        StringBuilder b = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (!Character.isISOControl(c)) {
                b.append(c);
            }
        }
        String t = b.toString().trim();
        if (t.isEmpty()) {
            return null;
        }
        if (t.length() > max) {
            int end = Character.isHighSurrogate(t.charAt(max - 1)) ? max - 1 : max;
            t = t.substring(0, end).trim();
        }
        return t;
    }

    private static String get(Supplier<String> supplier) {
        try {
            return supplier.get();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private static void put(Map<String, Object> m, String key, String value) {
        if (value != null) {
            m.put(key, value);
        }
    }

    static String json(Object value) {
        StringBuilder b = new StringBuilder(512);
        write(b, value);
        return b.toString();
    }

    private static void write(StringBuilder b, Object v) {
        if (v == null) {
            b.append("null");
        } else if (v instanceof Boolean || v instanceof Integer || v instanceof Long || v instanceof Short || v instanceof Byte) {
            b.append(v);
        } else if (v instanceof Number) {
            double d = ((Number) v).doubleValue();
            b.append(Double.isFinite(d) ? v.toString() : "null");
        } else if (v instanceof Map) {
            b.append('{');
            boolean firstEntry = true;
            for (Map.Entry<?, ?> e : ((Map<?, ?>) v).entrySet()) {
                if (!firstEntry) {
                    b.append(',');
                }
                firstEntry = false;
                quote(b, String.valueOf(e.getKey()));
                b.append(':');
                write(b, e.getValue());
            }
            b.append('}');
        } else if (v instanceof Collection) {
            b.append('[');
            boolean firstItem = true;
            for (Object item : (Collection<?>) v) {
                if (!firstItem) {
                    b.append(',');
                }
                firstItem = false;
                write(b, item);
            }
            b.append(']');
        } else {
            quote(b, v.toString());
        }
    }

    private static void quote(StringBuilder b, String s) {
        b.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':
                    b.append("\\\"");
                    break;
                case '\\':
                    b.append("\\\\");
                    break;
                case '\n':
                    b.append("\\n");
                    break;
                case '\r':
                    b.append("\\r");
                    break;
                case '\t':
                    b.append("\\t");
                    break;
                default:
                    if (c < 0x20 || c == 0x2028 || c == 0x2029) {
                        b.append(String.format("\\u%04x", (int) c));
                    } else {
                        b.append(c);
                    }
            }
        }
        b.append('"');
    }

    private static final class HttpTransport implements Transport {
        private final HttpClient http = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();

        @Override
        public Answer post(String url, Map<String, String> headers, byte[] body) throws IOException, InterruptedException {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(url)).timeout(TIMEOUT)
                    .POST(HttpRequest.BodyPublishers.ofByteArray(body));
            for (Map.Entry<String, String> h : headers.entrySet()) {
                request.header(h.getKey(), h.getValue());
            }
            HttpResponse<Void> res = http.send(request.build(), HttpResponse.BodyHandlers.discarding());
            return new Answer(res.statusCode(), res.headers().firstValue("Retry-After").orElse(null));
        }
    }

    /** Settings for one product's reporter; {@link #start()} never throws. */
    public static final class Builder {
        private String baseUrl = DEFAULT_BASE_URL;
        private String apiKey;
        private Supplier<String> licenseKey = () -> null;
        private String fingerprint;
        private String productAnalyticsId;
        private Path installIdFile;
        private Supplier<String> productVersion = () -> null;
        private String platformName;
        private String platformVersion;
        private BooleanSupplier enabled = () -> true;
        private Function<String, String> env = System::getenv;
        private Function<String, String> props = System::getProperty;
        private Transport transport;
        private Random random = new Random();
        private Duration firstDelay;

        private Builder() {
        }

        /** Defaults to {@value #DEFAULT_BASE_URL}. */
        public Builder baseUrl(String baseUrl) {
            if (baseUrl != null && !baseUrl.isBlank()) {
                this.baseUrl = baseUrl.trim();
            }
            return this;
        }

        /** Licensed products: the API key the product validates with ({@code slk_…}). */
        public Builder apiKey(String apiKey) {
            this.apiKey = apiKey;
            return this;
        }

        /** Licensed products: the license key it validates. */
        public Builder licenseKey(String licenseKey) {
            return licenseKey(() -> licenseKey);
        }

        /** The license key, read before each report (for products that pick up a new key while running). */
        public Builder licenseKey(Supplier<String> licenseKey) {
            this.licenseKey = licenseKey == null ? () -> null : licenseKey;
            return this;
        }

        /** Licensed products: the machine id it validates with ({@code fingerprint}, or {@code host} in /api/v2). */
        public Builder fingerprint(String fingerprint) {
            this.fingerprint = fingerprint;
            return this;
        }

        /** The product's public analytics id ({@code pa_…}): all a free product needs. */
        public Builder productAnalyticsId(String productAnalyticsId) {
            this.productAnalyticsId = productAnalyticsId;
            return this;
        }

        /**
         * Where this install keeps its random install id (a file {@value #INSTALL_ID_FILE}): the product's own
         * folder, e.g. a plugin's data folder. Defaults to {@code ~/.sunlicense}. Only used with a product
         * analytics id.
         */
        public Builder dataDirectory(Path directory) {
            if (directory != null) {
                this.installIdFile = directory.resolve(INSTALL_ID_FILE);
            }
            return this;
        }

        public Builder productVersion(String version) {
            return productVersion(() -> version);
        }

        public Builder productVersion(Supplier<String> version) {
            this.productVersion = version == null ? () -> null : version;
            return this;
        }

        /** Overrides the detected platform, e.g. {@code platform("myengine", "4.2")}. */
        public Builder platform(String name, String version) {
            this.platformName = name;
            this.platformVersion = version;
            return this;
        }

        /** The product's own switch (its config's {@code analytics: false}); false = nothing is sent. */
        public Builder enabled(boolean enabled) {
            return enabled(() -> enabled);
        }

        /** The product's switch, read before each report (for configs reloaded at runtime). */
        public Builder enabled(BooleanSupplier enabled) {
            this.enabled = enabled == null ? () -> true : enabled;
            return this;
        }

        Builder env(Function<String, String> env) {
            this.env = env;
            return this;
        }

        Builder props(Function<String, String> props) {
            this.props = props;
            return this;
        }

        Builder transport(Transport transport) {
            this.transport = transport;
            return this;
        }

        Builder random(Random random) {
            this.random = random;
            return this;
        }

        Builder firstDelay(Duration firstDelay) {
            this.firstDelay = firstDelay;
            return this;
        }

        /** A reporter that isn't started: it only sends when you call {@link SunLicenseAnalytics#sendNow()}. */
        public SunLicenseAnalytics build() {
            if (installIdFile == null) {
                String home = props.apply("user.home");
                installIdFile = Paths.get(home == null ? "." : home, ".sunlicense", INSTALL_ID_FILE);
            }
            return new SunLicenseAnalytics(this);
        }

        /** Starts reporting in the background (first report in 1–30 minutes). Never throws. */
        public SunLicenseAnalytics start() {
            try {
                return build().begin();
            } catch (RuntimeException e) {
                LOG.log(System.Logger.Level.DEBUG, "SunLicense analytics: not started: " + e);
                return new Builder().enabled(false).build();
            }
        }
    }
}
