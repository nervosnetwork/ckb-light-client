package com.nervosnetwork.ckblightclient

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import java.io.*

class LightClientService : Service() {
    private var isRunning = false
    private val TAG = "LightClientService"

    companion object {
        const val CHANNEL_ID = "ckb_light_client_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.nervosnetwork.ckblightclient.START"
        const val ACTION_STOP = "com.nervosnetwork.ckblightclient.STOP"
    }

    private val nativeStatusCallback = object : LightClientNative.StatusCallback {
        override fun onStatusChange(status: String, data: String) {
            Log.i(TAG, "Status changed: $status")
            when (status) {
                "initialized" -> updateNotification("Initialized")
                "running" -> updateNotification("Running")
                "stopped" -> updateNotification("Stopped")
                else -> updateNotification("Status: $status")
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> {
                startForegroundService()
                startLightClient()
            }
            ACTION_STOP -> {
                stopLightClient()
                stopSelf()
            }
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Log.d(TAG, "Creating notification channel for Android O+")
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CKB Light Client Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Running CKB Light Client in background"
            }
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
            Log.d(TAG, "Notification channel created successfully")
        } else {
            Log.d(TAG, "Android version < O, no notification channel needed")
        }
    }

    private fun startForegroundService() {
        val notification = createNotification("CKB Light Client is starting...")

        Log.d(TAG, "Starting foreground service with notification")
        appendLog("Starting foreground service...")

        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
            Log.d(TAG, "Foreground service started successfully")
            appendLog("Foreground service started - notification should be visible")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start foreground service", e)
            appendLog("ERROR starting foreground service: ${e.message}")
        }
    }

    private fun createNotification(contentText: String): Notification {
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, notificationIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CKB Light Client")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(text: String) {
        val notification = createNotification(text)
        val notificationManager = getSystemService(NotificationManager::class.java)
        notificationManager.notify(NOTIFICATION_ID, notification)
    }

    private fun startLightClient() {
        if (isRunning) {
            appendLog("Already running!")
            return
        }

        try {
            val configPath = File(filesDir, MainActivity.CONFIG_NAME).absolutePath

            appendLog("---")
            appendLog("Starting CKB Light Client via JNI...")
            appendLog("Config: $configPath")
            appendLog("---")

            // Initialize native light client
            val initSuccess = LightClientNative.nativeInit(
                configPath,
                nativeStatusCallback
            )

            if (!initSuccess) {
                appendLog("ERROR: Native initialization failed")
                stopSelf()
                return
            }

            appendLog("Native initialization succeeded")

            // Start the light client
            val startSuccess = LightClientNative.nativeStart()

            if (startSuccess) {
                isRunning = true
                appendLog("Light Client started successfully!")
                updateNotification("CKB Light Client is running")
            } else {
                appendLog("ERROR: Native start failed")
                stopSelf()
            }

        } catch (e: Exception) {
            appendLog("ERROR: ${e.message}")
            Log.e(TAG, "Start error", e)
            isRunning = false
            stopSelf()
        }
    }

    private fun stopLightClient() {
        if (!isRunning) {
            return
        }

        appendLog("---")
        appendLog("Stopping CKB Light Client...")
        updateNotification("CKB Light Client is stopping...")

        try {
            val stopSuccess = LightClientNative.nativeStop()
            if (stopSuccess) {
                appendLog("Light Client stopped successfully")
            } else {
                appendLog("WARNING: Native stop returned false")
            }
            appendLog("---")
        } catch (e: Exception) {
            appendLog("ERROR: ${e.message}")
            Log.e(TAG, "Stop error", e)
        } finally {
            isRunning = false
        }
    }

    private fun appendLog(message: String) {
        Log.d(TAG, message)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopLightClient()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}
