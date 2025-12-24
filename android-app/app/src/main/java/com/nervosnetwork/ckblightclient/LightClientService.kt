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
    private var isStarting = false
    private val TAG = "LightClientService"

    companion object {
        const val CHANNEL_ID = "ckb_light_client_channel"
        const val NOTIFICATION_ID = 1
        const val ACTION_START = "com.nervosnetwork.ckblightclient.START"
        const val ACTION_STOP = "com.nervosnetwork.ckblightclient.STOP"
        const val MAX_LOG_LINES = 5000

        var logCallback: ((String) -> Unit)? = null

        // Persistent log buffer that survives fragment lifecycle
        private val logBuffer = ArrayList<String>()

        fun getAllLogs(): List<String> {
            synchronized(logBuffer) {
                return ArrayList(logBuffer)
            }
        }

        fun clearLogs() {
            synchronized(logBuffer) {
                logBuffer.clear()
            }
        }

        private fun addLogLine(line: String) {
            synchronized(logBuffer) {
                logBuffer.add(line)
                // Keep only last 5000 lines
                if (logBuffer.size > MAX_LOG_LINES) {
                    logBuffer.removeAt(0)
                }
            }
        }
    }

    // JNI callbacks
    private val nativeLogCallback = object : LightClientNative.LogCallback {
        override fun onLog(level: String, messages: Array<String>) {
            val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
                .format(java.util.Date())
            messages.forEach { msg ->
                val formatted = "[$timestamp] [$level] $msg"
                Log.d(TAG, formatted)
                addLogLine(formatted)
                logCallback?.invoke(formatted)
            }
        }
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
        if (isRunning || isStarting) {
            appendLog("Already running or starting, please wait...")
            return
        }

        isStarting = true
        updateNotification("CKB Light Client is starting...")

        Thread {
            try {
                val configPath = File(filesDir, MainActivity.CONFIG_NAME).absolutePath

                appendLog("---")
                appendLog("Starting CKB Light Client via JNI (background thread)...")
                appendLog("Config: $configPath")
                appendLog("---")

                // Initialize native light client
            val initSuccess = LightClientNative.nativeInit(
                configPath,
                nativeLogCallback,
                nativeStatusCallback
            )

                if (!initSuccess) {
                    appendLog("ERROR: Native initialization failed")
                    stopSelf()
                    return@Thread
                }

                appendLog("Native initialization succeeded")

                // Apply saved RUST_LOG filter
                val prefs = getSharedPreferences("CKBLightClientPrefs", Context.MODE_PRIVATE)
                val savedFilter = prefs.getString("rust_log_filter", "TRACE") ?: "TRACE"
                val filterValue = savedFilter.lowercase()
                LightClientNative.nativeSetLogFilter(filterValue)
                appendLog("Applied log filter: $savedFilter")

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
            } finally {
                isStarting = false
            }
        }.start()
    }

    private fun stopLightClient() {
        if (isStarting) {
            appendLog("Still starting, please wait before stopping.")
            return
        }

        if (!isRunning) {
            appendLog("Not running!")
            return
        }

        appendLog("---")
        appendLog("Stopping CKB Light Client...")
        updateNotification("CKB Light Client is stopping...")

        // Run stop on background thread to avoid ANR (wait_all_ckb_services_exit blocks)
        Thread {
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
        }.start()
    }

    private fun appendLog(message: String) {
        val timestamp = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.getDefault())
            .format(java.util.Date())
        val logLine = "[$timestamp] $message"

        Log.d(TAG, message)
        addLogLine(logLine)
        logCallback?.invoke(logLine)
    }

    override fun onDestroy() {
        super.onDestroy()
        stopLightClient()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return null
    }
}
