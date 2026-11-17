package xyz.zivoralabs.toolip

import com.google.gson.Gson
import com.google.gson.JsonParser
import com.intellij.ide.impl.TrustedProjects
import com.intellij.ide.util.PropertiesComponent
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile
import java.nio.file.Path
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class ToolipSource(
    val relativePath: String,
    val content: String,
    val projectRoot: Path,
    val modificationStamp: Long
)

data class ToolipIssue(
    val line: Int,
    val column: Int,
    val message: String,
    val severity: String
)

data class ToolipAnalysis(
    val modificationStamp: Long,
    val issues: List<ToolipIssue>
)

/**
 * IDE buffers are passed as inert bounded text to the separately trusted
 * Toolip stdio protocol. No workspace scripts, environment secrets, network
 * providers or auto-fix operations are invoked by this plugin.
 */
class ToolipAnnotator : ExternalAnnotator<ToolipSource, ToolipAnalysis>() {
    override fun collectInformation(file: PsiFile): ToolipSource? {
        if (!TrustedProjects.isTrusted(file.project)) return null
        val settings = PropertiesComponent.getInstance()
        if (!settings.getBoolean("toolip.enabled", false)) return null
        if (settings.getValue("toolip.executablePath").isNullOrBlank()) return null
        val root = file.project.basePath ?: return null
        val physical = file.virtualFile?.path ?: return null
        val rootPath = runCatching { Path.of(root).toRealPath() }.getOrNull()
            ?: return null
        val absoluteFile = runCatching { Path.of(physical).toRealPath() }.getOrNull()
            ?: return null
        if (!absoluteFile.startsWith(rootPath)) return null
        val relative = runCatching {
            rootPath.relativize(absoluteFile).toString().replace('\\', '/')
        }.getOrNull() ?: return null
        if (
            relative.isEmpty() || relative.startsWith("../") ||
            relative.contains("/../") ||
            !Regex(".*\\.(?:[cm]?[jt]s|[jt]sx)$", RegexOption.IGNORE_CASE)
                .matches(relative)
        ) return null
        val beforeRevision = file.modificationStamp
        val text = file.text
        if (file.modificationStamp != beforeRevision ||
            text.toByteArray(Charsets.UTF_8).size > 512 * 1024)
            return null
        return ToolipSource(relative, text, rootPath, beforeRevision)
    }

    private fun incomplete(source: ToolipSource): ToolipAnalysis =
        ToolipAnalysis(source.modificationStamp, listOf(
            ToolipIssue(
                line = 1, column = 1, severity = "warning",
                message = "Toolip local analysis incomplete; no security all-clear."
            )
        ))

    override fun doAnnotate(collectedInfo: ToolipSource): ToolipAnalysis {
        if (!PropertiesComponent.getInstance().getBoolean("toolip.enabled", false))
            return incomplete(collectedInfo)
        val selected = PropertiesComponent.getInstance()
            .getValue("toolip.executablePath")
        val binary = ToolipPathPolicy.trustedExecutable(
            selected, collectedInfo.projectRoot
        ) ?: return incomplete(collectedInfo)
        val workingDirectory = ToolipPathPolicy.separateWorkingDirectory(
            collectedInfo.projectRoot
        ) ?: return incomplete(collectedInfo)
        val process = ProcessBuilder(binary.toString(), "ide", "serve")
            .directory(workingDirectory.toFile())
            .redirectErrorStream(false)
        val environment = process.environment()
        val inherited = System.getenv()
        environment.clear()
        for (name in listOf(
            "PATH", "HOME", "USERPROFILE", "SystemRoot", "TMPDIR", "TEMP"
        )) inherited[name]?.let { environment[name] = it }

        val child = runCatching { process.start() }.getOrNull()
            ?: return incomplete(collectedInfo)
        val gson = Gson()
        val worker = Executors.newSingleThreadExecutor { task ->
            Thread(task, "toolip-ide-analyzer").apply { isDaemon = true }
        }
        try {
            child.outputStream.bufferedWriter(Charsets.UTF_8).use { writer ->
                writer.write(gson.toJson(mapOf(
                    "jsonrpc" to "2.0", "id" to 1,
                    "method" to "textDocument/didOpen",
                    "params" to mapOf(
                        "path" to collectedInfo.relativePath,
                        "version" to 1,
                        "text" to collectedInfo.content
                    )
                )))
                writer.newLine()
                writer.write(gson.toJson(mapOf(
                    "jsonrpc" to "2.0", "id" to 2,
                    "method" to "textDocument/diagnostic",
                    "params" to mapOf("path" to collectedInfo.relativePath)
                )))
                writer.newLine()
                writer.flush()
            }
            val read = worker.submit<ToolipAnalysis> {
                child.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    // Both JSON-RPC requests have bounded response lines.
                    val opened = reader.readLine() ?: return@submit incomplete(collectedInfo)
                    if (opened.length > 512 * 1024)
                        return@submit incomplete(collectedInfo)
                    val line = reader.readLine() ?: return@submit incomplete(collectedInfo)
                    if (line.length > 512 * 1024)
                        return@submit incomplete(collectedInfo)
                    val result = runCatching {
                        JsonParser.parseString(line).asJsonObject
                    }.getOrNull() ?: return@submit incomplete(collectedInfo)
                    if (result.has("error") ||
                        result.get("id")?.asInt != 2)
                        return@submit incomplete(collectedInfo)
                    val payload = result.getAsJsonObject("result")
                        ?: return@submit incomplete(collectedInfo)
                    if (payload.get("version")?.asInt != 1 ||
                        payload.get("state")?.asString != "partial")
                        return@submit incomplete(collectedInfo)
                    val findings = payload.getAsJsonArray("findings")
                        ?: return@submit incomplete(collectedInfo)
                    val issues = findings.take(500).mapNotNull { element ->
                        val item = runCatching { element.asJsonObject }.getOrNull()
                            ?: return@mapNotNull null
                        val message = item.get("message")?.asString
                            ?.take(1024) ?: return@mapNotNull null
                        val lineNumber = item.get("line")?.asInt
                            ?: return@mapNotNull null
                        val column = item.get("column")?.asInt ?: 1
                        ToolipIssue(
                            line = lineNumber, column = column,
                            message = message,
                            severity = item.get("severity")?.asString ?: "medium"
                        )
                    }.toMutableList()
                    if (payload.get("findingsTruncated")?.asBoolean == true)
                        issues.add(ToolipIssue(
                            line = 1, column = 1, severity = "warning",
                            message = "Toolip findings exceeded the diagnostic budget; scan incomplete."
                        ))
                    ToolipAnalysis(collectedInfo.modificationStamp, issues)
                }
            }
            return read.get(8, TimeUnit.SECONDS)
        } catch (_: Exception) {
            return incomplete(collectedInfo)
        } finally {
            child.destroyForcibly()
            worker.shutdownNow()
        }
    }

    override fun apply(
        file: PsiFile,
        annotationResult: ToolipAnalysis,
        holder: AnnotationHolder
    ) {
        if (!TrustedProjects.isTrusted(file.project) ||
            file.modificationStamp != annotationResult.modificationStamp)
            return
        val document = PsiDocumentManager.getInstance(file.project)
            .getDocument(file) ?: return
        for (issue in annotationResult.issues) {
            if (issue.line < 1 || issue.line > document.lineCount) continue
            val lineIndex = issue.line - 1
            val start = document.getLineStartOffset(lineIndex)
            val end = document.getLineEndOffset(lineIndex)
            val position = (start + (issue.column - 1).coerceAtLeast(0))
                .coerceIn(start, end)
            val range = TextRange(
                position, (position + 1).coerceAtMost(document.textLength)
            )
            val severity = if (issue.severity == "critical" ||
                issue.severity == "high")
                HighlightSeverity.ERROR else HighlightSeverity.WARNING
            holder.newAnnotation(severity, issue.message)
                .range(range)
                .create()
        }
    }
}
