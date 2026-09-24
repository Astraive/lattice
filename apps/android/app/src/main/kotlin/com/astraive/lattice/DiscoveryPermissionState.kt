package com.astraive.lattice

/** Permission states shown to the user before any nearby scan is started. */
enum class DiscoveryPermissionState {
    NOT_REQUESTED,
    GRANTED,
    DENIED,
    PERMANENTLY_DENIED,
    REVOKED,
}

data class RuntimePermissionObservation(
    val granted: Boolean,
    val requestedBefore: Boolean,
    val shouldShowRationale: Boolean,
)

/** Pure classification so permission transitions can be tested without an Android device. */
object DiscoveryPermissionClassifier {
    fun classify(
        observations: List<RuntimePermissionObservation>,
        wasPreviouslyGranted: Boolean,
    ): DiscoveryPermissionState {
        if (observations.isEmpty()) {
            return DiscoveryPermissionState.NOT_REQUESTED
        }
        if (observations.all { it.granted }) {
            return DiscoveryPermissionState.GRANTED
        }
        if (wasPreviouslyGranted) {
            return DiscoveryPermissionState.REVOKED
        }
        if (observations.any { !it.granted && it.shouldShowRationale }) {
            return DiscoveryPermissionState.DENIED
        }
        if (observations.any { !it.granted && it.requestedBefore }) {
            return DiscoveryPermissionState.PERMANENTLY_DENIED
        }
        return DiscoveryPermissionState.NOT_REQUESTED
    }
}
