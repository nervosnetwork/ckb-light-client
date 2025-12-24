package com.nervosnetwork.ckblightclient

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.Log
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.nervosnetwork.ckblightclient.fragments.LogsFragment
import com.nervosnetwork.ckblightclient.fragments.StatusFragment
import java.io.File

class MainActivity : AppCompatActivity() {
    private lateinit var bottomNavigation: BottomNavigationView
    private val TAG = "CKBLightClient"

    companion object {
        const val CONFIG_NAME = "mainnet.toml"
        private const val NOTIFICATION_PERMISSION_REQUEST_CODE = 1001
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        bottomNavigation = findViewById(R.id.bottom_navigation)

        // Request notification permission for Android 13+
        requestNotificationPermission()

        // Setup binary and config
        setupBinaryAndConfig()

        // Load default fragment
        if (savedInstanceState == null) {
            loadFragment(LogsFragment())
        }

        // Setup bottom navigation
        bottomNavigation.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_logs -> {
                    loadFragment(LogsFragment())
                    true
                }
                R.id.nav_status -> {
                    loadFragment(StatusFragment())
                    true
                }
                else -> false
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.POST_NOTIFICATIONS
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.POST_NOTIFICATIONS),
                    NOTIFICATION_PERMISSION_REQUEST_CODE
                )
            }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        when (requestCode) {
            NOTIFICATION_PERMISSION_REQUEST_CODE -> {
                if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    Log.d(TAG, "Notification permission granted")
                } else {
                    Log.w(TAG, "Notification permission denied - foreground service notification will not show")
                }
            }
        }
    }

    private fun loadFragment(fragment: Fragment) {
        supportFragmentManager.beginTransaction()
            .replace(R.id.fragment_container, fragment)
            .commit()
    }

    private fun setupBinaryAndConfig() {
        try {
            // JNI mode: no need to extract binary, only setup config
            setupConfig()
            copySharedLibrary("libc++_shared.so")
        } catch (e: Exception) {
            Log.e(TAG, "Setup error", e)
        }
    }

    private fun copySharedLibrary(libName: String): File {
        val nativeLibDir = applicationInfo.nativeLibraryDir
        val sourceLib = File(nativeLibDir, libName)
        val destLib = File(filesDir, libName)

        if (!destLib.exists() || sourceLib.lastModified() > destLib.lastModified()) {
            sourceLib.copyTo(destLib, overwrite = true)
            destLib.setReadable(true, false)
        }

        return destLib
    }

    private fun setupConfig(): File {
        val configFile = File(filesDir, CONFIG_NAME)

        if (configFile.exists()) {
            val existing = runCatching { configFile.readText() }.getOrNull()
            if (existing != null && existing.contains("logger", ignoreCase = true)) {
                runCatching {
                    configFile.copyTo(File(configFile.parentFile, "$CONFIG_NAME.bak"), overwrite = true)
                }
                configFile.delete()
            } else {
                return configFile
            }
        }

        val configTemplate = assets.open(CONFIG_NAME).bufferedReader().use { it.readText() }
        val dataDir = File(filesDir, "data")
        dataDir.mkdirs()

        val modifiedConfig = configTemplate
            .replace("path = \"data/store\"", "path = \"${File(dataDir, "store").absolutePath}\"")
            .replace("path = \"data/network\"", "path = \"${File(dataDir, "network").absolutePath}\"")

        configFile.writeText(modifiedConfig)

        return configFile
    }
}
