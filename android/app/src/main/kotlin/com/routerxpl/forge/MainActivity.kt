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
private const val DEFAULT_CHROOT = "/kali"
private const val DEFAULT_ENGINE = "/opt/RouterXPL-Forge/engine/engine_cli.py"

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

class ResultsDb(context: Context) : SQLiteOpenHelper(context, "routerxpl_results.db", null, 1) {
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
    }

    override fun onUpgrade(db: SQLiteDatabase, oldVersion: Int, newVersion: Int) {
        db.execSQL("DROP TABLE IF EXISTS results")
        onCreate(db)
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

private fun shellQuote(value: String): String = "'" + value.replace("'", "'\\''") + "'"

private fun engineCall(context: Context, args: List<String>, timeoutSeconds: Long): JSONObject {
    val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
    val chroot = prefs.getString("chroot", DEFAULT_CHROOT)!!.trim()
    val engine = prefs.getString("engine", DEFAULT_ENGINE)!!.trim()
    val inner = buildString {
        append("python3 ").append(shellQuote(engine))
        args.forEach { append(' ').append(shellQuote(it)) }
    }
    val command = "chroot $chroot /bin/bash -lc $inner"
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
    var network by remember { mutableStateOf(prefs.getString("network", "192.168.1.0/24")!!) }
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

    fun runStep(args: List<String>, onOk: (JSONObject) -> Unit) {
        scope.launch {
            busy = true
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
        runStep(listOf("discover", "--network", network.trim())) { json ->
            devices = (json.optJSONArray("hosts") ?: JSONArray()).objects()
            selectedDevice = null
            fingerprint = null
            modules = emptyList()
            selectedModule = null
            lastResult = "Discovered ${devices.size} live device(s). Tap one to fingerprint."
        }
    }

    fun doFingerprint(host: JSONObject) {
        selectedDevice = host
        val target = host.optString("ip", "")
        runStep(listOf("fingerprint", "--target", target)) { json ->
            fingerprint = json.optJSONObject("host")
            modules = (json.optJSONArray("modules") ?: JSONArray()).objects()
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
                    selectedDevice = selectedDevice,
                    fingerprint = fingerprint,
                    modules = modules,
                    selectedModule = selectedModule,
                    lastResult = lastResult,
                    busy = busy,
                    onDiscover = { discover() },
                    onDevice = { doFingerprint(it) },
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
    selectedDevice: JSONObject?,
    fingerprint: JSONObject?,
    modules: List<JSONObject>,
    selectedModule: JSONObject?,
    lastResult: String,
    busy: Boolean,
    onDiscover: () -> Unit,
    onDevice: (JSONObject) -> Unit,
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
        StepHeader(1, "Discover live devices", "ARP / nmap / scapy sweep on your lab CIDR")
        OutlinedTextField(
            value = network,
            onValueChange = onNetworkChange,
            label = { Text("Target network") },
            placeholder = { Text("192.168.1.0/24") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
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

        StepHeader(2, "Fingerprint + modules", "Matched to vendor, model and open services")
        Card(colors = CardDefaults.cardColors(containerColor = DarkSurface)) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                if (fingerprint == null) {
                    Text("Tap a device to fingerprint it.", color = Muted, fontSize = 12.sp)
                } else {
                    Text("Target: ${fingerprint!!.optString("ip", selectedDevice?.optString("ip", "") ?: "")}", color = Color.White)
                    Text("Vendor: ${fingerprint!!.optString("vendor_guess", "unknown")}", color = Muted, fontSize = 12.sp)
                    Text("Model: ${fingerprint!!.optString("model_guess", "unknown")}", color = Muted, fontSize = 12.sp)
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
                                val title = meta.optString("name", mod.optString("title", ""))
                                val sev = meta.optString("severity", "")
                                Surface(
                                    color = if (selectedModule?.optString("path") == mod.optString("path")) DarkSurface2 else DarkSurface,
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .clickable { onModule(mod) },
                                ) {
                                    Column(Modifier.padding(10.dp)) {
                                        Text(mod.optString("path", ""), color = Green, fontSize = 12.sp, fontFamily = FontFamily.Monospace)
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
            "Run engine/install.sh inside the Kali chroot once, then set your lab CIDRs in allowed_networks.json.",
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
