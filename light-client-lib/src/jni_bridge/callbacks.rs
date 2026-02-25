//! JVM callback implementations
//!
//! Provides status callbacks for the light client.

use super::types::{JAVA_VM, STATUS_CALLBACK};

/// Invoke status callback
pub fn invoke_status_callback(status: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vm = JAVA_VM.get().ok_or("JavaVM not initialized")?;
    let callback_guard = STATUS_CALLBACK
        .lock()
        .map_err(|e| format!("Failed to lock STATUS_CALLBACK: {}", e))?;
    let callback = callback_guard.as_ref().ok_or("Status callback not set")?;

    // Attach current thread to JVM
    let mut env = vm.attach_current_thread()?;

    // Create strings
    let status_str = env.new_string(status)?;
    let data_str = env.new_string(data)?;

    // Call: void onStatusChange(String status, String data)
    env.call_method(
        callback.as_obj(),
        "onStatusChange",
        "(Ljava/lang/String;Ljava/lang/String;)V",
        &[
            jni::objects::JValue::Object(&status_str),
            jni::objects::JValue::Object(&data_str),
        ],
    )?;

    Ok(())
}
