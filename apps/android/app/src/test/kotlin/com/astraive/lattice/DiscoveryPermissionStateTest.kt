package com.astraive.lattice

import org.junit.Assert.assertEquals
import org.junit.Test

class DiscoveryPermissionStateTest {

    @Test
    fun missingPermissionObservationsDoNotAssumeAccess() {
        assertEquals(
            DiscoveryPermissionState.NOT_REQUESTED,
            DiscoveryPermissionClassifier.classify(emptyList(), wasPreviouslyGranted = false),
        )
    }
    @Test
    fun freshInstallRemainsNotRequested() {
        assertEquals(
            DiscoveryPermissionState.NOT_REQUESTED,
            DiscoveryPermissionClassifier.classify(
                listOf(observation(granted = false, requested = false, rationale = false)),
                wasPreviouslyGranted = false,
            ),
        )
    }

    @Test
    fun denialWithRationaleCanBeRequestedAgain() {
        assertEquals(
            DiscoveryPermissionState.DENIED,
            DiscoveryPermissionClassifier.classify(
                listOf(observation(granted = false, requested = true, rationale = true)),
                wasPreviouslyGranted = false,
            ),
        )
    }

    @Test
    fun requestedPermissionWithoutRationaleIsBlocked() {
        assertEquals(
            DiscoveryPermissionState.PERMANENTLY_DENIED,
            DiscoveryPermissionClassifier.classify(
                listOf(observation(granted = false, requested = true, rationale = false)),
                wasPreviouslyGranted = false,
            ),
        )
    }

    @Test
    fun permissionRevocationIsNotMisreportedAsPermanentDenial() {
        assertEquals(
            DiscoveryPermissionState.REVOKED,
            DiscoveryPermissionClassifier.classify(
                listOf(observation(granted = false, requested = true, rationale = false)),
                wasPreviouslyGranted = true,
            ),
        )
    }

    @Test
    fun everyRequiredPermissionMustBeGranted() {
        assertEquals(
            DiscoveryPermissionState.DENIED,
            DiscoveryPermissionClassifier.classify(
                listOf(
                    observation(granted = true, requested = true, rationale = false),
                    observation(granted = false, requested = true, rationale = true),
                ),
                wasPreviouslyGranted = false,
            ),
        )
    }

    @Test
    fun allRequiredPermissionsGrantedAreReady() {
        assertEquals(
            DiscoveryPermissionState.GRANTED,
            DiscoveryPermissionClassifier.classify(
                listOf(
                    observation(granted = true, requested = true, rationale = false),
                    observation(granted = true, requested = true, rationale = false),
                ),
                wasPreviouslyGranted = false,
            ),
        )
    }

    private fun observation(granted: Boolean, requested: Boolean, rationale: Boolean) =
        RuntimePermissionObservation(
            granted = granted,
            requestedBefore = requested,
            shouldShowRationale = rationale,
        )
}
