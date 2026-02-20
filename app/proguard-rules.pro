# NOX VPN ProGuard Rules

# Keep Kotlin metadata
-keep class kotlin.Metadata { *; }

# Keep coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Keep JSON parsing
-keepattributes *Annotation*
-keep class org.json.** { *; }

# Keep VPN service
-keep class com.nox.vpn.NoxVpnService { *; }
