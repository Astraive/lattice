package com.astraive.lattice

import android.Manifest
import android.annotation.SuppressLint
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.os.Build
import android.os.IBinder
import android.os.Handler
import android.os.Looper

internal object PersistentNearbyPermissionPolicy {
    fun requiresNotificationPermission(apiLevel: Int): Boolean =
        apiLevel >= Build.VERSION_CODES.TIRAMISU

    @SuppressLint("InlinedApi")
    fun hasNotificationPermission(context: Context): Boolean {
        if (
            requiresNotificationPermission(Build.VERSION.SDK_INT) &&
            context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return false
        }
        val manager = context.getSystemService(NotificationManager::class.java) ?: return false
        if (!manager.areNotificationsEnabled()) return false
        return Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
            manager.getNotificationChannel(PersistentNearbyService.CHANNEL_ID)?.importance !=
            NotificationManager.IMPORTANCE_NONE
    }

}
/** Keeps only a low-power, privacy-limited generic BLE scan alive while explicitly opted in. */
internal class PersistentNearbyService : Service() {
    private val preferences by lazy {
        getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
    }
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var nearbyScanner: NearbyServiceScanner
    private var bluetoothReceiverRegistered = false
    private var foregroundStarted = false

    private val bluetoothReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_OFF,
                BluetoothAdapter.STATE_TURNING_OFF -> {
                    nearbyScanner.stop()
                    publishStatus("Paused — Bluetooth is off. Turn it on to resume nearby discovery.")
                }
                BluetoothAdapter.STATE_ON -> startScanOrPause()
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        nearbyScanner = NearbyServiceScanner(
            context = applicationContext,
            onSightingsChanged = {},
            onFailure = { failure ->
                mainHandler.post {
                    if (isOptedIn(this)) {
                        if (!BleGattPermissionPolicy.hasConnectPermission(this) || !hasBleScanPermission()) {
                            stopMode("Persistent nearby mode stopped because Bluetooth permission was revoked.")
                        } else {
                            publishStatus("Paused — Android stopped BLE scanning ($failure). Stop and start the mode to retry.")
                        }
                    }
                }
            },
        )
        synchronized(instanceLock) { runningInstance = this }
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(bluetoothReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(bluetoothReceiver, filter)
        }
        bluetoothReceiverRegistered = true
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopMode("Persistent nearby mode stopped.")
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_START) setOptedIn(this, true)
        if (!isOptedIn(this)) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        if (!BleGattPermissionPolicy.hasConnectPermission(this) ||
            !PersistentNearbyPermissionPolicy.hasNotificationPermission(this)
        ) {
            stopMode("Persistent nearby mode stopped because a required permission is unavailable.")
            return START_NOT_STICKY
        }
        try {
            startForegroundWithNotification("Starting persistent nearby mode…")
            foregroundStarted = true
        } catch (_: SecurityException) {
            stopMode("Persistent nearby mode could not start. Review Bluetooth and notification permissions.")
            return START_NOT_STICKY
        } catch (_: RuntimeException) {
            stopMode("Android could not start the persistent nearby service.")
            return START_NOT_STICKY
        }
        startScanOrPause()
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        if (::nearbyScanner.isInitialized) nearbyScanner.stop()
        if (bluetoothReceiverRegistered) {
            unregisterReceiver(bluetoothReceiver)
            bluetoothReceiverRegistered = false
        }
        synchronized(instanceLock) {
            if (runningInstance === this) runningInstance = null
        }
        super.onDestroy()
    }

    private fun startScanOrPause() {
        if (!BleGattPermissionPolicy.hasConnectPermission(this) ||
            !hasBleScanPermission()
        ) {
            stopMode("Persistent nearby mode stopped because Bluetooth permission was revoked.")
            return
        }
        when (nearbyScanner.start()) {
            NearbyServiceScanner.StartResult.STARTED -> publishStatus(
                "Active — scanning for generic service signals only. Sightings are unauthenticated; no GATT connection or message exchange is available.",
            )
            NearbyServiceScanner.StartResult.BLUETOOTH_OFF -> publishStatus(
                "Paused — Bluetooth is off. Turn it on to resume nearby discovery.",
            )
            NearbyServiceScanner.StartResult.PERMISSION_MISSING -> stopMode(
                "Persistent nearby mode stopped because Bluetooth permission was revoked.",
            )
            NearbyServiceScanner.StartResult.ADAPTER_UNAVAILABLE,
            NearbyServiceScanner.StartResult.SCANNER_UNAVAILABLE,
            NearbyServiceScanner.StartResult.FAILED -> stopMode(
                "Persistent nearby discovery is unavailable on this device.",
            )
        }
    }

    private fun hasBleScanPermission(): Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        checkSelfPermission(Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED
    } else {
        checkSelfPermission(Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
    }

    private fun publishStatus(status: String) {
        if (!PersistentNearbyPermissionPolicy.hasNotificationPermission(this)) {
            stopMode("Persistent nearby mode stopped because notification permission was revoked.")
            return
        }
        try {
            getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, notification(status))
        } catch (_: SecurityException) {
            stopMode("Persistent nearby mode stopped because Android blocked its status notification.")
            return
        }
        setOptedIn(this, true)
        sendStatus(enabled = true, status = status)
    }

    private fun stopMode(status: String) {
        nearbyScanner.stop()
        setOptedIn(this, false)
        sendStatus(enabled = false, status = status)
        if (foregroundStarted) {
            stopForeground(STOP_FOREGROUND_REMOVE)
            foregroundStarted = false
        }
        stopSelf()
    }

    @SuppressLint("MissingPermission")
    private fun startForegroundWithNotification(status: String) {
        val foregroundNotification = notification(status)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NOTIFICATION_ID,
                foregroundNotification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
            )
        } else {
            startForeground(NOTIFICATION_ID, foregroundNotification)
        }
    }

    private fun notification(status: String): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            OPEN_REQUEST_CODE,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this,
            STOP_REQUEST_CODE,
            Intent(this, PersistentNearbyService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setContentTitle("Lattice persistent nearby mode")
            .setContentText(status)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setContentIntent(openIntent)
            .addAction(
                Notification.Action.Builder(
                    Icon.createWithResource(this, android.R.drawable.ic_menu_close_clear_cancel),
                    "Stop",
                    stopIntent,
                ).build(),
            )
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Persistent nearby mode",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shows when opt-in nearby discovery is running or paused."
                setShowBadge(false)
            }
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun sendStatus(enabled: Boolean, status: String) {
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_ENABLED, enabled)
                .putExtra(EXTRA_STATUS, status),
        )
    }

    internal companion object {
        const val ACTION_START = "com.astraive.lattice.action.START_PERSISTENT_NEARBY"
        const val ACTION_STOP = "com.astraive.lattice.action.STOP_PERSISTENT_NEARBY"
        const val ACTION_STATUS = "com.astraive.lattice.action.PERSISTENT_NEARBY_STATUS"
        const val EXTRA_ENABLED = "enabled"
        const val EXTRA_STATUS = "status"
        private const val PREFERENCES_NAME = "persistent_nearby_mode"
        private const val KEY_OPTED_IN = "opted_in"
        const val CHANNEL_ID = "persistent_nearby_mode"
        private const val NOTIFICATION_ID = 4102
        private const val OPEN_REQUEST_CODE = 4103
        private const val STOP_REQUEST_CODE = 4104
        private val instanceLock = Any()
        @Volatile private var runningInstance: PersistentNearbyService? = null

        fun isOptedIn(context: Context): Boolean =
            context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_OPTED_IN, false)

        fun isRunning(): Boolean = runningInstance != null

        private fun setOptedIn(context: Context, enabled: Boolean) {
            context.getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_OPTED_IN, enabled)
                .apply()
        }
    }
}
