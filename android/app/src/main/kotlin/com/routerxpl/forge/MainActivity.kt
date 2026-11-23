package com.routerxpl.forge

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.database.sqlite.SQLiteDatabase
import android.database.sqlite.SQLiteOpenHelper
import android.os.Bundle
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.TimeUnit

private const val PREFS = "routerxpl_prefs"
private const val DEFAULT_CHROOT = "/data/local/nhsystem/kali-arm64"
private const val DEFAULT_ENGINE = "/opt/RouterXPL-Forge/engine/engine_cli.py"
private const val DEFAULT_PYTHON = "/opt/RouterXPL-Forge/.venv/bin/python"

private val Green = Color(0xFF6EE787)
private val DarkBg = Color(0xFF080C0A)
private val DarkSurface = Color(0xFF111A14)
private val DarkSurface2 = Color(0xFF17231B)
private val Muted = Color(0xFF9FB3A6)
private val Danger = Color(0xFFFF6B6B)
private val Amber = Color(0xFFFFC857)

private val AppColors = darkColorScheme(
    primary = Green,
    onPrimary = Color(0xFF04150A),
    primaryContainer = Color(0xFF1B3A25),
    onPrimaryContainer = Green,
    secondary = Color(0xFF81C784),
    tertiary = Amber,
    background = DarkBg,
    onBackground = Color(0xFFE6F4EA),
    surface = DarkSurface,
    onSurface = Color(0xFFE6F4EA),
    surfaceVariant = DarkSurface2,
    onSurfaceVariant = Muted,
    error = Danger,
    onError = Color(0xFF2A0505),
)

data class ResultEntry(
    val ts: String,
    val command: String,
    val target: String,
    val module: String,
    val ok: Boolean,
    val vulnerable: String?,
    val detail: String?,
)

data class KnownDevice(
    val ts: String,
    val ip: String,
    val mac: String,
    val vendor: String,
    val hostname: String,
)

class ResultsDb(context: Context) : SQLiteOpenHelper(context, "routerxpl_results.db", null, 2) {
    override fun onCreate(db: SQLiteDatabase) {
        db.execSQL(
            """
            CREATE TABLE results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                command TEXT NOT NULL,
                target TEXT NOT NULL,
                module TEXT NOT NULL,
                ok INTEGER NOT NULL,
                vulnerable TEXT,
                detail TEXT
            )
            """.trimIndent(),
        )
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS known_devices (
                ip TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                mac TEXT NOT NULL,
                vendor TEXT,
                hostname TEXT
            )
            """.trimIndent(),
        )
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        if (oldVersion < 1) {
            db.execSQL("DROP TABLE IF EXISTS results")
        }
        db.execSQL(
            """
            CREATE TABLE IF NOT EXISTS known_devices (
                ip TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                mac TEXT NOT NULL,
                vendor TEXT,
                hostname TEXT
            )
            """.trimIndent(),
        )
    }

    fun insert(entry: ResultEntry) {
        writableDatabase.execSQL(
            "INSERT INTO results(ts,command,target,module,ok,vulnerable,detail) VALUES(?,?,?,?,?,?,?)",
            arrayOf(
                entry.ts,
                entry.command,
                entry.target,
                entry.module,
                if (entry.ok) 1 else 0,
                entry.vulnerable,
                entry.detail,
            ),
        )
    }

    fun all(): List<ResultEntry> {
        val out = mutableListOf<ResultEntry>()
        val cursor: Cursor = readableDatabase.rawQuery(
            "SELECT ts,command,target,module,ok,vulnerable,detail FROM results ORDER BY id DESC",
            null,
        )
        cursor.use {
            while (it.moveToNext()) {
                out.add(
                    ResultEntry(
                        ts = it.getString(0),
                        command = it.getString(1),
                        target = it.getString(2),
                        module = it.getString(3),
                        ok = it.getInt(4) == 1,
                        vulnerable = it.getString(5),
                        detail = it.getString(6),
                    ),
                )
            }
        }
        return out
    }

    fun upsertKnown(hosts: List<JSONObject>) {
        val db = writableDatabase
        val ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())
        hosts.forEach { host ->
            val ip = host.optString("ip", "").trim()
            val mac = host.optString("mac", "").trim()
            if (ip.isEmpty() || mac.isEmpty()) return@forEach
            db.execSQL(
                "INSERT OR REPLACE INTO known_devices(ip,ts,mac,vendor,hostname) VALUES(?,?,?,?,?)",
                arrayOf(
                    ip,
                    ts,
                    mac,
                    host.optString("vendor_guess", ""),
                    host.optString("hostname", ""),
                ),
            )
        }
    }

    fun allKnown(): List<KnownDevice> {
        val out = mutableListOf<KnownDevice>()
        val cursor: Cursor = readableDatabase.rawQuery(
            "SELECT ts,ip,mac,vendor,hostname FROM known_devices ORDER BY ts DESC",
            null,
        )
        cursor.use {
            while (it.moveToNext()) {
                out.add(
                    KnownDevice(
                        ts = it.getString(0),
                        ip = it.getString(1),
                        mac = it.getString(2),
                        vendor = it.getString(3) ?: "",
                        hostname = it.getString(4) ?: "",
                    ),
                )
            }
        }
        return out
    }

    fun toJson(): String {
        val arr = JSONArray()
        all().forEach { e ->
            arr.put(
                JSONObject().apply {
                    put("ts", e.ts)
                    put("command", e.command)
                    put("target", e.target)
                    put("module", e.module)
                    put("ok", e.ok)
                    put("vulnerable", e.vulnerable)
                    put("detail", e.detail)
                },
            )
        }
        return JSONObject().put("sessions", arr).toString(2)
    }
}

fun JSONArray.objects(): List<JSONObject> = (0 until length()).map { getJSONObject(it) }

private fun ipv4ToInt(ip: String): Long? {
    val parts = ip.trim().split(".")
    if (parts.size != 4) return null
    var value = 0L
    for (part in parts) {
        val octet = part.toIntOrNull() ?: return null
        if (octet < 0 || octet > 255) return null
        value = (value shl 8) or octet.toLong()
    }
    return value
}

private fun ipInCidr(ip: String, cidr: String): Boolean {
    val parts = cidr.trim().split("/")
    if (parts.size != 2) return ip.trim() == cidr.trim()
    val network = ipv4ToInt(parts[0]) ?: return false
    val prefix = parts[1].toIntOrNull() ?: return false
    val address = ipv4ToInt(ip) ?: return false
    if (prefix < 0 || prefix > 32) return false
    if (prefix == 0) return true
    val mask = (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
    return (network and mask) == (address and mask)
}

private fun isValidPrivateCidr(value: String): Boolean {
    val parts = value.trim().split("/")
    if (parts.size != 2) return false
    val address = ipv4ToInt(parts[0]) ?: return false
    val prefix = parts[1].toIntOrNull() ?: return false
    if (prefix < 8 || prefix > 32) return false
    val mask = (0xFFFFFFFFL shl (32 - prefix)) and 0xFFFFFFFFL
    val network = address and mask
    return when {
        prefix >= 8 && (network and 0xFF000000L) == 0x0A000000L -> true
        prefix >= 12 && (network and 0xFFF00000L) == 0xAC100000L -> true
        prefix >= 16 && (network and 0xFFFF0000L) == 0xC0A80000L -> true
        else -> false
    }
}

private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

private fun engineCall(context: Context, args: List<String>, timeoutSeconds: Long): JSONObject {
    val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val chroot = prefs.getString("chroot", DEFAULT_CHROOT)!!.trim()
    val engine = prefs.getString("engine", DEFAULT_ENGINE)!!.trim()
    val python = prefs.getString("python", DEFAULT_PYTHON)!!.trim().ifEmpty { DEFAULT_PYTHON }
    val inner = buildString {
        append(shellQuote(python)).append(' ').append(shellQuote(engine))
        args.forEach { append(' ').append(shellQuote(it)) }
    }
    // The whole inner command must be a single argument to bash -lc; otherwise
    // bash only receives the interpreter path and leaves the script/args unused.
    val command = "chroot ${shellQuote(chroot)} /bin/bash -lc ${shellQuote(inner)}"
    return try {
        val process = ProcessBuilder("su", "-c", command)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        val finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS)
        if (!finished) {
            process.destroyForcibly()
            return JSONObject().put("ok", false).put("error", "Engine timed out")
        }
        val lines = output.lines().map { it.trim() }.filter { it.startsWith("{") }
        val last = lines.lastOrNull()
            ?: return JSONObject().put("ok", false)
                .put("error", "No JSON from engine (exit ${process.exitValue()}): ${output.take(200)}")
        try {
            JSONObject(last)
        } catch (exc: Exception) {
            JSONObject().put("ok", false).put("error", "Bad engine JSON: ${exc.message}")
        }
    } catch (exc: Exception) {
        JSONObject().put("ok", false)
            .put("error", "Cannot run engine: ${exc.message}. Root granted / chroot running?")
    }
}

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val db = ResultsDb(this)
        setContent {
            MaterialTheme(colorScheme = AppColors) {
                Surface(modifier = Modifier.fillMaxSize(), color = DarkBg) {
                    AppShell(db = db) { args, timeout -> engineCall(this@MainActivity, args, timeout) }
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppShell(db: ResultsDb, engine: (List<String>, Long) -> JSONObject) {
    val context = LocalContext.current
    val prefs = remember { context.getSharedPreferences(PREFS, Context.MODE_PRIVATE) }
    val scope = rememberCoroutineScope()

    var tab by remember { mutableStateOf(0) }
    var busy by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Checking engine...") }
    var network by remember { mutableStateOf(prefs.getString("network", "192.168.0.0/24")!!) }
    var chroot by remember { mutableStateOf(prefs.getString("chroot", DEFAULT_CHROOT)!!) }
    var enginePath by remember { mutableStateOf(prefs.getString("engine", DEFAULT_ENGINE)!!) }

    var devices by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var selectedDevice by remember { mutableStateOf<JSONObject?>(null) }
    var fingerprint by remember { mutableStateOf<JSONObject?>(null) }
    var modules by remember { mutableStateOf<List<JSONObject>>(emptyList()) }
    var selectedModule by remember { mutableStateOf<JSONObject?>(null) }
    var lastResult by remember { mutableStateOf("No results yet. Run a safe check to begin.") }
    var results by remember { mutableStateOf(db.all()) }
    var showConfirm by remember { mutableStateOf(false) }
    var confirmText by remember { mutableStateOf("") }
    var knownDevices by remember { mutableStateOf(db.allKnown()) }
    var sleepingDevices by remember { mutableStateOf<List<KnownDevice>>(emptyList()) }
    var lastScannedNetwork by remember { mutableStateOf(network.trim()) }
    var wakeTarget by remember { mutableStateOf<KnownDevice?>(null) }

    fun runStep(args: List<String>, before: List<String>? = null, onOk: (JSONObject) -> Unit) {
        scope.launch {
            busy = true
            if (before != null) {
                status = "Saving lab CIDR ..."
                val prepared = withContext(Dispatchers.IO) { engine(before, 60) }
                if (!prepared.optBoolean("ok", false)) {
                    busy = false
                    val err = prepared.optString("error", "Could not save lab CIDR")
                    status = err
                    lastResult = "Error: $err"
                    return@launch
                }
            }
            status = "Running ${args.first()} ..."
            val json = withContext(Dispatchers.IO) { engine(args, 600) }
            busy = false
            if (json.optBoolean("ok", false)) {
                status = "Engine ready"
                onOk(json)
            } else {
                val err = json.optString("error", "Unknown error")
                status = err
                lastResult = "Error: $err"
            }
        }
    }

    LaunchedEffect(Unit) {
        val json = withContext(Dispatchers.IO) { engine(listOf("doctor"), 40) }
        status = if (json.optBoolean("ok", false)) {
            "Ready · ${json.optInt("module_count", 0)} modules"
        } else {
            json.optString("error", "Engine error")
        }
    }

    fun discover() {
        val scanned = network.trim()
        if (!isValidPrivateCidr(scanned)) {
            status = "Enter a private IPv4 CIDR, e.g. 192.168.0.0/24"
            lastResult = "Invalid target network: $scanned"
            return
        }
        runStep(
            listOf("discover", "--network", scanned),
            before = listOf("allow", "--network", scanned)
        ) { json ->
            devices = (json.optJSONArray("hosts") ?: JSONArray()).objects()
            selectedDevice = null
            fingerprint = null
            modules = emptyList()
            selectedModule = null
            db.upsertKnown(devices)
            knownDevices = db.allKnown()
            lastScannedNetwork = scanned
            val liveIps = devices.mapNotNull { it.optString("ip", "").takeIf { v -> v.isNotEmpty() } }.toSet()
            sleepingDevices = knownDevices.filter { device ->
                device.mac.matches(Regex("^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")) &&
                    ipInCidr(device.ip, scanned) &&
                    device.ip !in liveIps
            }
            lastResult = "Allowlist set to $scanned. " +
                "Discovered ${devices.size} live device(s). " +
                "${sleepingDevices.size} saved device(s) appear asleep."
        }
    }

    fun wake(device: KnownDevice) {
        runStep(listOf("wol", "--mac", device.mac, "--network", lastScannedNetwork)) { _ ->
            lastResult = "Wake-on-LAN sent to ${device.ip} (${device.mac})."
        }
    }

    fun doFingerprint(host: JSONObject) {
        selectedDevice = host
        val target = host.optString("ip", "")
        runStep(listOf("fingerprint", "--target", target)) { json ->
            fingerprint = json.optJSONObject("host")
            modules = (json.optJSONArray("modules") ?: JSONArray()).objects()
                .sortedWith(
                    compareByDescending<JSONObject> { it.optInt("score", -100) }
                        .thenBy { it.optString("path", "") }
                )
            selectedModule = null
            lastResult = "Fingerprinted $target · ${modules.size} relevant module(s)."
        }
    }

    fun execute(command: String) {
        val target = selectedDevice?.optString("ip", "")
        val module = selectedModule?.optString("path", "")
        if (target.isNullOrEmpty() || module.isNullOrEmpty()) {
            Toast.makeText(context, "Select a device and module first", Toast.LENGTH_SHORT).show()
            return
        }
        val args = mutableListOf(command, "--module", module, "--target", target)
        if (command == "run") args.addAll(listOf("--confirm", "I_AUTHORIZE"))
        runStep(args) { json ->
            val vulnerable = if (json.has("vulnerable")) json.opt("vulnerable").toString() else null
            val output = json.optString("output", "")
            val error = json.optString("error", "")
            lastResult = buildString {
                append("${command.uppercase()} · $target · $module\n")
                append("Vulnerable: ${vulnerable ?: "n/a"}\n")
                if (error.isNotEmpty()) append("Error: $error\n")
                if (output.isNotEmpty()) append("\n${output.takeLast(1200)}")
            }
            db.insert(
                ResultEntry(
                    ts = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date()),
                    command = command,
                    target = target,
                    module = module,
                    ok = json.optBoolean("ok", false),
                    vulnerable = vulnerable,
                    detail = (error + "\n" + output).take(4000),
                ),
            )
            results = db.all()
        }
    }

    if (showConfirm) {
        val target = selectedDevice?.optString("ip", "") ?: ""
        AlertDialog(
            onDismissRequest = { showConfirm = false },
            title = { Text("Authorize exploit", color = Danger) },
            text = {
                Column {
                    Text(
                        "This will run ${selectedModule?.optString("path", "")} against $target.\n\n" +
                            "Only continue on hardware you own or have written permission to test. " +
                            "The target must be inside your allowed_networks.json lab range.",
                        color = Muted,
                        fontSize = 13.sp,
                    )
                    Spacer(Modifier.height(12.dp))
                    OutlinedTextField(
                        value = confirmText,
                        onValueChange = { confirmText = it },
                        label = { Text("Type $target to confirm") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                }
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        showConfirm = false
                        execute("run")
                    },
                    enabled = confirmText.trim() == target,
                ) { Text("RUN EXPLOIT") }
            },
            dismissButton = { TextButton(onClick = { showConfirm = false }) { Text("Cancel") } },
        )
    }

    if (wakeTarget != null) {
        val target = wakeTarget!!
        AlertDialog(
            onDismissRequest = { wakeTarget = null },
            title = { Text("Wake device", color = Green) },
            text = {
                Text(
                    "Send a Wake-on-LAN magic packet to ${target.mac} (${target.ip})?\n\n" +
                        "Only wake hardware you own on your lab network.",
                    color = Muted,
                    fontSize = 13.sp,
                )
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        wakeTarget = null
                        wake(target)
                    },
                    enabled = !busy,
                ) { Text("WAKE") }
            },
            dismissButton = { TextButton(onClick = { wakeTarget = null }) { Text("Cancel") } },
        )
    }

    Scaffold(
        containerColor = DarkBg,
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("RouterXPL-Forge", fontWeight = FontWeight.Bold)
                        Text(status, fontSize = 11.sp, color = Muted)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = DarkSurface,
                    titleContentColor = Color.White,
                ),
            )
        },
        bottomBar = {
            NavigationBar(containerColor = DarkSurface) {
                val items = listOf(
                    Triple(0, Icons.Filled.Search, "Scan"),
                    Triple(1, Icons.Filled.List, "Sessions"),
                    Triple(2, Icons.Filled.Settings, "Setup"),
                )
                items.forEach { (index, icon, label) ->
                    NavigationBarItem(
                        selected = tab == index,
                        onClick = {
                            tab = index
                            if (index == 1) results = db.all()
                        },
                        icon = { Icon(icon, contentDescription = label) },
                        label = { Text(label) },
                        colors = NavigationBarItemDefaults.colors(
                            selectedIconColor = Green,
                            selectedTextColor = Green,
                            unselectedIconColor = Muted,
                            unselectedTextColor = Muted,
                            indicatorColor = DarkSurface2,
                        ),
                    )
                }
            }
        },
    ) { padding ->
        Column(Modifier.padding(padding).fillMaxSize()) {
            if (busy) {
                LinearProgressIndicator(
                    modifier = Modifier.fillMaxWidth().height(3.dp),
                    color = Green,
                    trackColor = DarkSurface2,
                )
            }
            when (tab) {
                0 -> WorkflowTab(
                    network = network,
                    onNetworkChange = {
                        network = it
                        prefs.edit().putString("network", it).apply()
                    },
                    devices = devices,
                    sleepingDevices = sleepingDevices,
                    selectedDevice = selectedDevice,
                    fingerprint = fingerprint,
                    modules = modules,
                    selectedModule = selectedModule,
                    lastResult = lastResult,
                    busy = busy,
                    onDiscover = { discover() },
                    onDevice = { doFingerprint(it) },
                    onWake = { wakeTarget = it },
                    onModule = { selectedModule = it },
                    onCheck = { execute("check") },
                    onRun = {
                        confirmText = ""
                        showConfirm = true
                    },
                )
                1 -> SessionsTab(
                    results = results,
                    onShare = {
                        val intent = Intent(Intent.ACTION_SEND).apply {
                            type = "application/json"
                            putExtra(Intent.EXTRA_SUBJECT, "RouterXPL-Forge sessions")
                            putExtra(Intent.EXTRA_TEXT, db.toJson())
                        }
                        context.startActivity(Intent.createChooser(intent, "Share sessions"))
                    },
                )
                2 -> SetupTab(
                    chroot = chroot,
                    enginePath = enginePath,
                    onChrootChange = { chroot = it },
                    onEngineChange = { enginePath = it },
                    onSave = {
                        prefs.edit()
                            .putString("chroot", chroot.trim())
                            .putString("engine", enginePath.trim())
                            .apply()
                        Toast.makeText(context, "Setup saved", Toast.LENGTH_SHORT).show()
                        scope.launch {
                            val json = withContext(Dispatchers.IO) { engine(listOf("doctor"), 40) }
                            status = if (json.optBoolean("ok", false)) {
                                "Ready · ${json.optInt("module_count", 0)} modules"
                            } else {
                                json.optString("error", "Engine error")
                            }
                        }
                    },
                )
            }
        }
    }
}

@Composable
fun StepHeader(number: Int, title: String, subtitle: String) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Surface(
            shape = RoundedCornerShape(10.dp),
            color = Green,
            modifier = Modifier.size(28.dp),
        ) {
            Box(contentAlignment = Alignment.Center) {
                Text("$number", color = DarkBg, fontWeight = FontWeight.Bold, fontSize = 14.sp)
            }
        }
        Spacer(Modifier.width(10.dp))
        Column {
            Text(title, fontWeight = FontWeight.Bold, fontSize = 15.sp, color = Color.White)
            Text(subtitle, fontSize = 11.sp, color = Muted)
        }
    }
}

@Composable
fun WorkflowTab(
    network: String,
    onNetworkChange: (String) -> Unit,
    devices: List<JSONObject>,
    sleepingDevices: List<KnownDevice>,
    selectedDevice: JSONObject?,
    fingerprint: JSONObject?,
    modules: List<JSONObject>,
    selectedModule: JSONObject?,
    lastResult: String,
    busy: Boolean,
    onDiscover: () -> Unit,
    onDevice: (JSONObject) -> Unit,
    onWake: (KnownDevice) -> Unit,
    onModule: (JSONObject) -> Unit,
    onCheck: () -> Unit,
    onRun: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp),
    ) {
        StepHeader(1, "Discover live devices", "Type a private CIDR; Discover saves it to the allowlist automatically")
        OutlinedTextField(
            value = network,
            onValueChange = onNetworkChange,
            label = { Text("Target network (CIDR)") },
            placeholder = { Text("192.168.0.0/24") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            "Discover writes this CIDR to allowed_networks.json, then scans it. RFC1918 ranges only.",
            color = Muted,
            fontSize = 11.sp,
        )
        Button(
            onClick = onDiscover,
            enabled = !busy,
            modifier = Modifier.fillMaxWidth(),
            colors = ButtonDefaults.buttonColors(containerColor = Green, contentColor = DarkBg),
        ) { Text("DISCOVER") }

        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
            Column(Modifier.padding(12.dp)) {
                Text("Devices", fontWeight = FontWeight.Bold, color = Color.White)
                Spacer(Modifier.height(6.dp))
                if (devices.isEmpty()) {
                    Text("No devices yet. Run a discovery first.", color = Muted, fontSize = 12.sp)
                } else {
                    LazyColumn(Modifier.heightIn(max = 220.dp)) {
                        itemsIndexed(devices) { _, host ->
                            val ip = host.optString("ip", "?")
                            val vendor = host.optString("vendor_guess", "")
                            val ports = host.optJSONArray("open_ports")?.toString() ?: "-"
                            val modCount = host.optJSONArray("matched_modules")?.length() ?: 0
                            Surface(
                                color = if (selectedDevice?.optString("ip") == ip) DarkSurface2 else DarkSurface,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { onDevice(host) },
                            ) {
                                Column(Modifier.padding(10.dp)) {
                                    Text(ip, fontWeight = FontWeight.Bold, color = Green)
                                    Text(
                                        listOfNotNull(
                                            vendor.ifEmpty { null }?.let { "vendor: $it" },
                                            "ports: $ports",
                                            "modules: $modCount",
                                        ).joinToString(" · "),
                                        fontSize = 11.sp,
                                        color = Muted,
                                    )
                                }
                            }
                            Divider(color = DarkSurface2)
                        }
                    }
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
            Column(Modifier.padding(12.dp)) {
                Text("Sleeping / offline devices", fontWeight = FontWeight.Bold, color = Color.White)
                Spacer(Modifier.height(6.dp))
                if (sleepingDevices.isEmpty()) {
                    Text(
                        "No saved devices are missing from the last scan.",
                        color = Muted,
                        fontSize = 12.sp,
                    )
                } else {
                    LazyColumn(Modifier.heightIn(max = 200.dp)) {
                        itemsIndexed(sleepingDevices) { _, device ->
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(device.ip, fontWeight = FontWeight.Bold, color = Amber)
                                    Text(
                                        listOfNotNull(
                                            device.mac,
                                            device.vendor.ifEmpty { null },
                                        ).joinToString(" · "),
                                        fontSize = 11.sp,
                                        color = Muted,
                                    )
                                }
                                OutlinedButton(
                                    onClick = { onWake(device) },
                                    enabled = !busy,
                                ) { Text("WAKE") }
                            }
                            Divider(color = DarkSurface2)
                        }
                    }
                }
            }
        }

        StepHeader(2, "Fingerprint + modules", "Matched to vendor, model and open services")
        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (fingerprint == null) {
                    Text("Tap a device to fingerprint it.", color = Muted, fontSize = 12.sp)
                } else {
                    Text("Target: ${fingerprint!!.optString("ip", selectedDevice?.optString("ip", "") ?: "")}", color = Color.White)
                    Text("Vendor: ${fingerprint!!.optString("vendor_guess", "").ifEmpty { "Unknown" }}", color = Muted, fontSize = 12.sp)
                    Text("Model: ${fingerprint!!.optString("model_guess", "").ifEmpty { "Unknown" }}", color = Muted, fontSize = 12.sp)
                    Row {
                        AssistChip(
                            onClick = {},
                            label = { Text("confidence ${fingerprint!!.optDouble("fingerprint_confidence", 0.0)}") },
                            colors = AssistChipDefaults.assistChipColors(
                                containerColor = DarkSurface2,
                                labelColor = Green,
                            ),
                        )
                    }
                    if (modules.isEmpty()) {
                        Text("No modules matched this fingerprint.", color = Amber, fontSize = 12.sp)
                    } else {
                        LazyColumn(Modifier.heightIn(max = 200.dp)) {
                            itemsIndexed(modules) { _, mod ->
                                val meta = mod.optJSONObject("metadata") ?: JSONObject()
                                val title = meta.optString("name", "").ifEmpty { mod.optString("title", "").ifEmpty { "Unknown" } }
                                val sev = meta.optString("severity", "")
                                val likelyFail = mod.optBoolean("likely_fail", false)
                                Surface(
                                    color = if (selectedModule?.optString("path") == mod.optString("path")) DarkSurface2 else DarkSurface,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { onModule(mod) },
                                ) {
                                    Column(Modifier.padding(10.dp)) {
                                        Row(verticalAlignment = Alignment.CenterVertically) {
                                            Text(
                                                mod.optString("path", ""),
                                                color = Green,
                                                fontSize = 12.sp,
                                                fontFamily = FontFamily.Monospace,
                                                modifier = Modifier.weight(1f),
                                            )
                                            if (likelyFail) {
                                                Text(
                                                    "LIKELY FAIL",
                                                    color = Danger,
                                                    fontSize = 9.sp,
                                                    fontWeight = FontWeight.Bold,
                                                    modifier = Modifier
                                                        .background(Color(0xFF3A1414))
                                                        .padding(horizontal = 5.dp, vertical = 2.dp),
                                                )
                                            }
                                        }
                                        if (title.isNotEmpty()) Text(title, color = Color.White, fontSize = 12.sp)
                                        if (sev.isNotEmpty()) Text("severity: $sev", color = Amber, fontSize = 11.sp)
                                    }
                                }
                                Divider(color = DarkSurface2)
                            }
                        }
                    }
                }
            }
        }

        StepHeader(3, "Checks and exploits", "Safe check by default · exploit needs confirmation")
        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                if (selectedModule == null) {
                    Text("Select a module above.", color = Muted, fontSize = 12.sp)
                } else {
                    val meta = selectedModule!!.optJSONObject("metadata") ?: JSONObject()
                    Text(selectedModule!!.optString("path", ""), color = Green, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                    Text(meta.optString("description", "").take(180), color = Muted, fontSize = 12.sp)
                    val matchReason = selectedModule!!.optString("reason", "")
                    if (matchReason.isNotEmpty()) {
                        Text("Match: $matchReason", color = Muted, fontSize = 11.sp)
                    }
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(
                            onClick = onCheck,
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                        ) { Text("SAFE CHECK") }
                        Button(
                            onClick = onRun,
                            enabled = !busy,
                            modifier = Modifier.weight(1f),
                            colors = ButtonDefaults.buttonColors(containerColor = Danger, contentColor = Color.White),
                        ) { Text("RUN EXPLOIT") }
                    }
                }
            }
        }

        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface2)) {
            Text(
                lastResult,
                color = Color.White,
                fontSize = 12.sp,
                fontFamily = FontFamily.Monospace,
                modifier = Modifier.padding(12.dp),
            )
        }
        Spacer(Modifier.height(20.dp))
    }
}

@Composable
fun SessionsTab(results: List<ResultEntry>, onShare: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Sessions & results", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color.White)
            Spacer(Modifier.weight(1f))
            Button(onClick = onShare, colors = ButtonDefaults.buttonColors(containerColor = Green, contentColor = DarkBg)) {
                Text("SHARE JSON")
            }
        }
        Spacer(Modifier.height(12.dp))
        if (results.isEmpty()) {
            Text("No results yet.", color = Muted)
        } else {
            LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                itemsIndexed(results) { _, e ->
                    Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
                        Column(Modifier.padding(12.dp)) {
                            Text("${e.command.uppercase()} · ${e.ts}", color = Green, fontSize = 12.sp, fontWeight = FontWeight.Bold)
                            Text("${e.target} → ${e.module}", color = Color.White, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                            Text("vulnerable=${e.vulnerable ?: "n/a"} · ok=${e.ok}", color = if (e.ok) Green else Amber, fontSize = 11.sp)
                            if (!e.detail.isNullOrEmpty()) {
                                Text(e.detail!!.take(260), color = Muted, fontSize = 11.sp, fontFamily = FontFamily.Monospace)
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun SetupTab(
    chroot: String,
    enginePath: String,
    onChrootChange: (String) -> Unit,
    onEngineChange: (String) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("NetHunter setup", fontWeight = FontWeight.Bold, fontSize = 18.sp, color = Color.White)
        Text(
            "Run engine/install.sh inside the Kali chroot once. You no longer need to edit allowed_networks.json; type the lab CIDR on the Scan tab and tap Discover.",
            color = Muted,
            fontSize = 12.sp,
        )
        OutlinedTextField(
            value = chroot,
            onValueChange = onChrootChange,
            label = { Text("Chroot path") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        OutlinedTextField(
            value = enginePath,
            onValueChange = onEngineChange,
            label = { Text("Engine CLI path") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true,
        )
        Button(onClick = onSave, modifier = Modifier.fillMaxWidth(), colors = ButtonDefaults.buttonColors(containerColor = Green, contentColor = DarkBg)) {
            Text("SAVE & VERIFY")
        }
        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface2)) {
            Text(
                "Authorized testing only. Exploits are blocked until the target is inside your own allowed_networks.json and you retype the IP to confirm.",
                color = Amber,
                fontSize = 12.sp,
                modifier = Modifier.padding(12.dp),
            )
        }
    }
}
