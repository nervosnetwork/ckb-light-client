package com.nervosnetwork.ckblightclient.fragments

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ScrollView
import android.widget.TextView
import androidx.fragment.app.Fragment
import com.nervosnetwork.ckblightclient.R
import java.io.BufferedReader
import java.io.InputStreamReader

class LogsFragment : Fragment() {
    private lateinit var logsText: TextView
    private lateinit var scrollView: ScrollView
    private val handler = Handler(Looper.getMainLooper())
    private val updateInterval = 1000L
    private val maxLogLines = 500
    private var logcatProcess: Process? = null
    private var isUserScrolling = false
    private val scrollThreshold = 50

    private val updateRunnable = object : Runnable {
        override fun run() {
            updateLogs()
            handler.postDelayed(this, updateInterval)
        }
    }

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_logs, container, false)
        logsText = view.findViewById(R.id.logs_text)
        scrollView = view.findViewById(R.id.logs_scroll)
        return view
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        scrollView.viewTreeObserver.addOnScrollChangedListener {
            val scrollY = scrollView.scrollY
            val childHeight = scrollView.getChildAt(0).height
            val viewHeight = scrollView.height
            val distanceFromBottom = childHeight - viewHeight - scrollY
            
            isUserScrolling = distanceFromBottom > scrollThreshold
        }
        
        startLogcat()
    }

    override fun onResume() {
        super.onResume()
        handler.post(updateRunnable)
    }

    override fun onPause() {
        super.onPause()
        handler.removeCallbacks(updateRunnable)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        stopLogcat()
    }

    private fun startLogcat() {
        try {
            // Start logcat process filtering for our tag
            // -v time: Show timestamps
            // -s ckb-light-client:*: Show only ckb-light-client tag
            logcatProcess = Runtime.getRuntime().exec(
                arrayOf("logcat", "-v", "time", "-s", "ckb-light-client:*", "LightClientService:*")
            )
        } catch (e: Exception) {
            logsText.text = "Failed to start logcat: ${e.message}"
        }
    }

    private fun stopLogcat() {
        logcatProcess?.destroy()
        logcatProcess = null
    }

    private fun updateLogs() {
        try {
            val process = logcatProcess ?: return
            val reader = BufferedReader(InputStreamReader(process.inputStream))

            val lines = mutableListOf<String>()
            var line: String?

            while (reader.ready() && lines.size < maxLogLines) {
                line = reader.readLine()
                if (line != null) {
                    lines.add(line)
                }
            }

            if (lines.isNotEmpty()) {
                val currentText = logsText.text.toString()
                val currentLines = if (currentText.isEmpty() || currentText == "Waiting for logs...\n") {
                    emptyList()
                } else {
                    currentText.split("\n")
                }

                val allLines = (currentLines + lines).takeLast(maxLogLines)
                logsText.text = allLines.joinToString("\n")
                
                if (!isUserScrolling) {
                    scrollView.post {
                        scrollView.fullScroll(View.FOCUS_DOWN)
                    }
                }
            } else if (logsText.text.isEmpty()) {
                logsText.text = "Waiting for logs...\n"
            }
        } catch (e: Exception) {
            logsText.text = "Error reading logs: ${e.message}"
        }
    }
}
