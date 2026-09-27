package com.astraive.lattice

import android.Manifest
import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.p2p.WifiP2pManager
import android.os.Build

internal enum class WifiCapabilityState {
    NOT_PROBED,
    AVAILABLE,
    TEMPORARILY_UNAVAILABLE,
    PERMISSION_REQUIRED,
    UNSUPPORTED,
}

internal data class AndroidWifiCapabilities(
    val aware: WifiCapabilityState = WifiCapabilityState.NOT_PROBED,
    val direct: WifiCapabilityState = WifiCapabilityState.NOT_PROBED,
    val lan: WifiCapabilityState = WifiCapabilityState.NOT_PROBED,
)

internal object WifiCapabilityPolicy {
    @SuppressLint("InlinedApi")
    fun requiredRuntimePermission(apiLevel: Int): String =
        if (apiLevel >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.NEARBY_WIFI_DEVICES
        } else {
            Manifest.permission.ACCESS_FINE_LOCATION
        }

    fun classify(
        featurePresent: Boolean,
        availableNow: Boolean,
        permissionGranted: Boolean,
    ): WifiCapabilityState = when {
        !featurePresent -> WifiCapabilityState.UNSUPPORTED
        !permissionGranted -> WifiCapabilityState.PERMISSION_REQUIRED
        availableNow -> WifiCapabilityState.AVAILABLE
        else -> WifiCapabilityState.TEMPORARILY_UNAVAILABLE
    }
}

/** Reports local capability only; it never treats a candidate as a connected or authenticated path. */
internal object AndroidWifiCapabilityProbe {
    fun probe(context: Context): AndroidWifiCapabilities {
        val appContext = context.applicationContext
        val packageManager = appContext.packageManager
        val pathPermission = hasNearbyWifiPermission(appContext)

        val awareSupported = packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE)
        val aware = if (!awareSupported) {
            WifiCapabilityState.UNSUPPORTED
        } else if (!pathPermission) {
            WifiCapabilityState.PERMISSION_REQUIRED
        } else {
            try {
                val manager = appContext.getSystemService(WifiAwareManager::class.java)
                WifiCapabilityPolicy.classify(
                    featurePresent = true,
                    availableNow = manager?.isAvailable == true,
                    permissionGranted = true,
                )
            } catch (_: SecurityException) {
                WifiCapabilityState.PERMISSION_REQUIRED
            } catch (_: RuntimeException) {
                WifiCapabilityState.TEMPORARILY_UNAVAILABLE
            }
        }

        val directSupported = packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_DIRECT)
        val direct = if (!directSupported) {
            WifiCapabilityState.UNSUPPORTED
        } else if (!pathPermission) {
            WifiCapabilityState.PERMISSION_REQUIRED
        } else {
            try {
                WifiCapabilityPolicy.classify(
                    featurePresent = true,
                    availableNow = appContext.getSystemService(WifiP2pManager::class.java) != null,
                    permissionGranted = true,
                )
            } catch (_: SecurityException) {
                WifiCapabilityState.PERMISSION_REQUIRED
            } catch (_: RuntimeException) {
                WifiCapabilityState.TEMPORARILY_UNAVAILABLE
            }
        }

        val lan = probeLan(appContext)
        return AndroidWifiCapabilities(aware = aware, direct = direct, lan = lan)
    }

    private fun hasNearbyWifiPermission(context: Context): Boolean =
        context.checkSelfPermission(WifiCapabilityPolicy.requiredRuntimePermission(Build.VERSION.SDK_INT)) ==
            PackageManager.PERMISSION_GRANTED

    private fun probeLan(context: Context): WifiCapabilityState {
        val connectivity = context.getSystemService(ConnectivityManager::class.java)
            ?: return WifiCapabilityState.TEMPORARILY_UNAVAILABLE
        if (context.checkSelfPermission(Manifest.permission.ACCESS_NETWORK_STATE) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return WifiCapabilityState.PERMISSION_REQUIRED
        }
        return try {
            val network = connectivity.activeNetwork
            val capabilities = network?.let(connectivity::getNetworkCapabilities)
            val localTransport = capabilities?.let {
                it.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    it.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
            } == true
            // A local Wi-Fi/Ethernet network can work without internet; this is only an interface hint.
            WifiCapabilityPolicy.classify(
                featurePresent = true,
                availableNow = localTransport,
                permissionGranted = true,
            )
        } catch (_: SecurityException) {
            WifiCapabilityState.PERMISSION_REQUIRED
        } catch (_: RuntimeException) {
            WifiCapabilityState.TEMPORARILY_UNAVAILABLE
        }
    }
}
