//! JVM callback implementations
//!
//! Provides log and status callbacks with 100ms batching for efficiency.

use super::types::{JAVA_VM, LOG_CALLBACK, STATUS_CALLBACK};
use jni::objects::{JObject, JValue};
use jni::sys::jobjectArray;
use jni::JNIEnv;
use log::{Level, LevelFilter, Log, Metadata, Record};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

/// Log buffer for batching
struct LogBuffer {
    entries: Vec<(Level, String)>,
    last_flush: Instant,
}

impl LogBuffer {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            last_flush: Instant::now(),
        }
    }

    fn should_flush(&self) -> bool {
        self.last_flush.elapsed() >= Duration::from_millis(100) || self.entries.len() >= 50
    }
}

static LOG_BUFFER: Mutex<Option<LogBuffer>> = Mutex::new(None);

/// Log filter configuration supporting RUST_LOG format
struct LogFilterConfig {
    default_level: LevelFilter,
    module_filters: Vec<(String, LevelFilter)>,
}

impl LogFilterConfig {
    const fn new() -> Self {
        Self {
            // Default to debug for normal diagnostics; can be overridden via nativeSetLogFilter()
            default_level: LevelFilter::Debug,
            module_filters: Vec::new(),
        }
    }

    fn should_log(&self, metadata: &Metadata) -> bool {
        let target = metadata.target();
        let level = metadata.level();

        // Check module-specific filters first
        for (module, module_level) in &self.module_filters {
            if target.starts_with(module) {
                return level <= *module_level;
            }
        }

        // Fall back to default level
        level <= self.default_level
    }
}

/// Global log filter for RUST_LOG-style filtering
static LOG_FILTER: RwLock<LogFilterConfig> = RwLock::new(LogFilterConfig::new());

/// Update log filter from RUST_LOG-style string
/// Examples: "info", "debug", "info,ckb_network=debug", "info,ckb_sync=trace,ckb_network=debug"
pub fn set_log_filter(rust_log: &str) {
    let mut config = LogFilterConfig::new();

    // Parse RUST_LOG format
    for directive in rust_log.split(',') {
        let directive = directive.trim();
        if directive.is_empty() {
            continue;
        }

        if let Some((module, level_str)) = directive.split_once('=') {
            // Module-specific: "ckb_network=debug"
            if let Ok(level) = level_str.trim().parse::<LevelFilter>() {
                config
                    .module_filters
                    .push((module.trim().to_string(), level));
            }
        } else {
            // Global level: "debug"
            if let Ok(level) = directive.parse::<LevelFilter>() {
                config.default_level = level;
            }
        }
    }

    // Update global filter
    if let Ok(mut filter) = LOG_FILTER.write() {
        *filter = config;
        log::set_max_level(LevelFilter::Trace); // Allow all, filtering in enabled()
    }
}

/// JNI Logger implementation with batching and RUST_LOG-style filtering
pub struct JniLogger;

impl Log for JniLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        if let Ok(filter) = LOG_FILTER.read() {
            filter.should_log(metadata)
        } else {
            metadata.level() <= LevelFilter::Info
        }
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let mut buffer_guard = LOG_BUFFER.lock().unwrap();
        let buffer = buffer_guard.get_or_insert_with(LogBuffer::new);

        // Mimic env_logger default: include target/module path in the message
        let message = format!("{}: {}", record.target(), record.args());
        buffer.entries.push((record.level(), message));

        // Flush immediately to avoid losing short bursts (mobile app often emits only a few lines)
        flush_log_buffer(buffer);
    }

    fn flush(&self) {
        let mut buffer_guard = LOG_BUFFER.lock().unwrap();
        if let Some(buffer) = buffer_guard.as_mut() {
            flush_log_buffer(buffer);
        }
    }
}

/// Flush log buffer and invoke JVM callback
fn flush_log_buffer(buffer: &mut LogBuffer) {
    if buffer.entries.is_empty() {
        return;
    }

    // Group by level for efficiency
    let mut grouped: std::collections::HashMap<Level, Vec<String>> =
        std::collections::HashMap::new();
    for (level, msg) in buffer.entries.drain(..) {
        grouped.entry(level).or_insert_with(Vec::new).push(msg);
    }

    // Invoke callback for each level
    for (level, messages) in grouped {
        if let Err(e) = invoke_log_callback_internal(level, &messages) {
            eprintln!("Failed to invoke log callback: {:?}", e);
        }
    }

    buffer.last_flush = Instant::now();
}

/// Internal function to invoke log callback
fn invoke_log_callback_internal(
    level: Level,
    messages: &[String],
) -> Result<(), Box<dyn std::error::Error>> {
    let vm = JAVA_VM.get().ok_or("JavaVM not initialized")?;
    let callback = LOG_CALLBACK.get().ok_or("Log callback not set")?;

    // Attach current thread to JVM
    let mut env = vm.attach_current_thread()?;

    // Create level string
    let level_str = env.new_string(level.to_string())?;

    // Create String array
    let messages_array = create_string_array(&mut env, messages)?;

    // Call: void onLog(String level, String[] messages)
    env.call_method(
        callback.as_obj(),
        "onLog",
        "(Ljava/lang/String;[Ljava/lang/String;)V",
        &[
            JValue::Object(&level_str),
            JValue::Object(unsafe { &JObject::from_raw(messages_array) }),
        ],
    )?;

    // env is automatically detached when dropped
    Ok(())
}

/// Public function to invoke log callback
pub fn invoke_log_callback(level: Level, messages: &[String]) {
    if let Err(e) = invoke_log_callback_internal(level, messages) {
        eprintln!("Failed to invoke log callback: {:?}", e);
    }
}

/// Invoke status callback
pub fn invoke_status_callback(status: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
    let vm = JAVA_VM.get().ok_or("JavaVM not initialized")?;
    let callback = STATUS_CALLBACK.get().ok_or("Status callback not set")?;

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
        &[JValue::Object(&status_str), JValue::Object(&data_str)],
    )?;

    Ok(())
}

/// Helper to create String array from Vec<String>
fn create_string_array(
    env: &mut JNIEnv,
    strings: &[String],
) -> Result<jobjectArray, Box<dyn std::error::Error>> {
    let string_class = env.find_class("java/lang/String")?;
    let empty_string = env.new_string("")?;

    let array = env.new_object_array(strings.len() as i32, string_class, empty_string)?;

    for (i, s) in strings.iter().enumerate() {
        let jstr = env.new_string(s)?;
        env.set_object_array_element(&array, i as i32, jstr)?;
    }

    Ok(array.into_raw())
}

/// Force flush on demand (called on stop)
pub fn flush_logs() {
    let mut buffer_guard = LOG_BUFFER.lock().unwrap();
    if let Some(buffer) = buffer_guard.as_mut() {
        flush_log_buffer(buffer);
    }
}
