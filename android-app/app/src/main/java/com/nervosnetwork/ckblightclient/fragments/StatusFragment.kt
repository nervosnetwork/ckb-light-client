package com.nervosnetwork.ckblightclient.fragments

import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonParser
import com.nervosnetwork.ckblightclient.LightClientNative
import com.nervosnetwork.ckblightclient.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class StatusFragment : Fragment() {
    private lateinit var peersText: TextView
    private lateinit var tipHeaderText: TextView
    private lateinit var scriptsText: TextView
    private lateinit var refreshButton: Button
    private lateinit var rpcMethodInput: EditText
    private lateinit var rpcParamsInput: EditText
    private lateinit var rpcCallButton: Button
    private lateinit var rpcResultText: TextView

    private val gson = Gson()

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        val view = inflater.inflate(R.layout.fragment_status, container, false)
        
        peersText = view.findViewById(R.id.peers_text)
        tipHeaderText = view.findViewById(R.id.tip_header_text)
        scriptsText = view.findViewById(R.id.scripts_text)
        refreshButton = view.findViewById(R.id.refresh_button)
        rpcMethodInput = view.findViewById(R.id.rpc_method_input)
        rpcParamsInput = view.findViewById(R.id.rpc_params_input)
        rpcCallButton = view.findViewById(R.id.rpc_call_button)
        rpcResultText = view.findViewById(R.id.rpc_result_text)
        
        return view
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)
        
        refreshButton.setOnClickListener {
            refreshAllData()
        }
        
        rpcCallButton.setOnClickListener {
            callCustomRpc()
        }
        
        refreshAllData()
    }

    private fun refreshAllData() {
        lifecycleScope.launch {
            updatePeers()
            updateTipHeader()
            updateScripts()
        }
    }

    private suspend fun updatePeers() {
        withContext(Dispatchers.IO) {
            android.util.Log.d("StatusFragment", "Calling get_peers RPC...")
            val responseJson = LightClientNative.callRpc("get_peers")
            android.util.Log.d("StatusFragment", "get_peers response: $responseJson")
            withContext(Dispatchers.Main) {
                if (responseJson == null) {
                    android.util.Log.e("StatusFragment", "get_peers returned null!")
                    peersText.text = "Error: Failed to call RPC"
                    return@withContext
                }

                try {
                    val response = gson.fromJson(responseJson, com.google.gson.JsonObject::class.java)

                    if (response.has("error")) {
                        val error = response.getAsJsonObject("error")
                        peersText.text = "Error: ${error.get("message").asString}"
                        return@withContext
                    }

                    val peers = response.getAsJsonArray("result")
                    peersText.text = if (peers.size() == 0) {
                        "No peers connected"
                    } else {
                        buildString {
                            append("Connected peers: ${peers.size()}\n\n")
                            peers.forEach { peer ->
                                val peerObj = peer.asJsonObject
                                val nodeId = peerObj.get("node_id")?.asString?.take(16) ?: "unknown"
                                val connectedDurationHex = peerObj.get("connected_duration")?.asString ?: "0x0"
                                val connectedDuration = connectedDurationHex.removePrefix("0x").toLongOrNull(16) ?: 0
                                val durationMinutes = connectedDuration / 60000
                                append("• $nodeId... ($durationMinutes min)\n")
                            }
                        }
                    }
                } catch (e: Exception) {
                    peersText.text = "Error parsing response: ${e.message}"
                }
            }
        }
    }

    private suspend fun updateTipHeader() {
        withContext(Dispatchers.IO) {
            val responseJson = LightClientNative.callRpc("get_tip_header")
            withContext(Dispatchers.Main) {
                if (responseJson == null) {
                    tipHeaderText.text = "Error: Failed to call RPC"
                    return@withContext
                }

                try {
                    val response = gson.fromJson(responseJson, com.google.gson.JsonObject::class.java)

                    if (response.has("error")) {
                        val error = response.getAsJsonObject("error")
                        tipHeaderText.text = "Error: ${error.get("message").asString}"
                        return@withContext
                    }

                    val header = response.getAsJsonObject("result")
                    val number = header.get("number")?.asString ?: "0"
                    val hash = header.get("hash")?.asString ?: "unknown"
                    val timestamp = header.get("timestamp")?.asString ?: "0"

                    tipHeaderText.text = buildString {
                        append("Block Number: $number\n")
                        append("Hash: ${hash.take(16)}...\n")
                        append("Timestamp: $timestamp\n")
                    }
                } catch (e: Exception) {
                    tipHeaderText.text = "Error parsing response: ${e.message}"
                }
            }
        }
    }

    private suspend fun updateScripts() {
        withContext(Dispatchers.IO) {
            val responseJson = LightClientNative.callRpc("get_scripts")
            withContext(Dispatchers.Main) {
                if (responseJson == null) {
                    scriptsText.text = "Error: Failed to call RPC"
                    return@withContext
                }

                try {
                    val response = gson.fromJson(responseJson, com.google.gson.JsonObject::class.java)

                    if (response.has("error")) {
                        val error = response.getAsJsonObject("error")
                        scriptsText.text = "Error: ${error.get("message").asString}"
                        return@withContext
                    }

                    val scripts = response.getAsJsonArray("result")
                    scriptsText.text = if (scripts.size() == 0) {
                        "No scripts monitored"
                    } else {
                        buildString {
                            append("Monitored scripts: ${scripts.size()}\n\n")
                            scripts.forEach { script ->
                                val scriptObj = script.asJsonObject
                                val scriptType = scriptObj.get("script_type")?.asString ?: "unknown"
                                val scriptData = scriptObj.getAsJsonObject("script")
                                val codeHash = scriptData.get("code_hash")?.asString?.take(16) ?: "unknown"
                                val blockNumber = scriptObj.get("block_number")?.asString ?: "0"
                                append("• $scriptType: $codeHash... (from block $blockNumber)\n")
                            }
                        }
                    }
                } catch (e: Exception) {
                    scriptsText.text = "Error parsing response: ${e.message}"
                }
            }
        }
    }

    private fun callCustomRpc() {
        val method = rpcMethodInput.text.toString().trim()

        if (method.isEmpty()) {
            rpcResultText.text = "Please enter an RPC method"
            return
        }

        lifecycleScope.launch {
            withContext(Dispatchers.IO) {
                val responseJson = LightClientNative.callRpc(method)
                withContext(Dispatchers.Main) {
                    if (responseJson == null) {
                        rpcResultText.text = "Error: Failed to call RPC"
                        return@withContext
                    }

                    try {
                        // Pretty print the JSON response
                        val response = gson.fromJson(responseJson, com.google.gson.JsonObject::class.java)
                        rpcResultText.text = gson.toJson(response)
                    } catch (e: Exception) {
                        rpcResultText.text = "Error parsing response: ${e.message}"
                    }
                }
            }
        }
    }
}
