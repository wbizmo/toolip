package xyz.zivoralabs.toolip

import com.google.gson.Gson
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.ide.impl.TrustedProjects
import com.intellij.openapi.editor.Document
import com.intellij.openapi.util.TextRange
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.psi.PsiDocumentManager
import com.intellij.psi.PsiFile
import com.intellij.ide.util.PropertiesComponent
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

data class ToolipSource(val relativePath: String, val content: String)
data class ToolipIssue(val line: Int, val column: Int, val message: String, val severity: String)

class ToolipAnnotator : ExternalAnnotator<ToolipSource, List<ToolipIssue>>() {
    override fun collectInformation(file: PsiFile): ToolipSource? {
        val project = file.project
        if (!TrustedProjects.isTrusted(project)) return null
        val executable = PropertiesComponent.getInstance()
            .getValue("toolip.executablePath") ?: return null
        if (executable.isBlank()) return null

        val root = project.basePath ?: return null
        val physical = file.virtualFile?.path ?: return null
        val source = file.text
        if (source.toByteArray(Charsets.UTF_8).size > 512 * 1024) return null
        val rootPath = Path.of(root).toAbsolutePath().normalize()
        val relative = runCatching {
            rootPath.relativize(Path.of(physical).toAbsolutePath().normalize())
        }.getOrNull() ?: return null
        val candidate = relative.toString().replace('\\', '/')
        if (candidate == ".." || candidate.startsWith("../") ||
            candidate.startsWith("/") ||
            !Regex(".*\\.(?:[cm]?[jt]s|[jt]sx)$", RegexOption.IGNORE_CASE).matches(candidate)
        ) return null
        return ToolipSource(candidate, source)
    }

    override fun doAnnotate(collectedInfo: ToolipSource): List<ToolipIssue> {
        val executable = PropertiesComponent.getInstance()
            .getValue("toolip.executablePath") ?: return emptyList()
        val binary = runCatching { Path.of(executable).toAbsolutePath().normalize() }
            .getOrNull() ?: return emptyList()
        if (!binary.isAbsolute || !Files.isRegularFile(binary) || !Files.isExecutable(binary))
            return emptyList()

        val process = ProcessBuilder(binary.toString(), "ide", "serve")
            .redirectErrorStream(false)
        val environment = process.environment()
        val inherited = System.getenv()
        environment.clear()
        for (key in listOf("PATH", "HOME", "USERPROFILE", "SystemRoot", "TMPDIR", "TEMP")) {
            inherited[key]?.let { environment[key] = it }
        }
        val child = runCatching { process.start() }.getOrNull() ?: return emptyList()
        val gson = Gson()
        val worker = Executors.newSingleThreadExecutor()
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
            val read = worker.submit<List<ToolipIssue>> {
                child.inputStream.bufferedReader(Charsets.UTF_8).use { reader ->
                    reader.readLine() ?: return@submit emptyList()
                    val line = reader.readLine() ?: return@submit emptyList()
                    if (line.length > 512 * 1024) return@submit emptyList()
                    val result = runCatching {
                        JsonParser.parseString(line).asJsonObject
                    }.getOrNull() ?: return@submit emptyList()
                    if (result.has("error")) return@submit emptyList()
                    val diagnostics = result.getAsJsonObject("result")
                        ?.getAsJsonArray("findings") ?: return@submit emptyList()
                    diagnostics.take(500).mapNotNull { element ->
                        val item = runCatching { element.asJsonObject }.getOrNull()
                            ?: return@mapNotNull null
                        val message = item.get("message")?.asString
                            ?.take(1024) ?: return@mapNotNull null
                        val lineNo = item.get("line")?.asInt ?: return@mapNotNull null
                        val columnNo = item.get("column")?.asInt ?: 1
                        ToolipIssue(
                            line = lineNo, column = columnNo,
                            message = message,
                            severity = item.get("severity")?.asString ?: "medium"
                        )
                    }
                }
            }
            return read.get(8, TimeUnit.SECONDS)
        } catch (_: Exception) {
            return emptyList()
        } finally {
            child.destroyForcibly()
            worker.shutdownNow()
        }
    }

    override fun apply(
        file: PsiFile,
        annotationResult: List<ToolipIssue>,
        holder: AnnotationHolder
    ) {
        val document = PsiDocumentManager.getInstance(file.project)
            .getDocument(file) ?: return
        for (issue in annotationResult) {
            if (issue.line < 1 || issue.line > document.lineCount) continue
            val line = issue.line - 1
            val start = document.getLineStartOffset(line)
            val end = document.getLineEndOffset(line)
            val location = (start + (issue.column - 1).coerceAtLeast(0))
                .coerceIn(start, end)
            val range = TextRange(location, (location + 1).coerceAtMost(document.textLength))
            val severity = if (issue.severity == "critical" || issue.severity == "high")
                HighlightSeverity.ERROR else HighlightSeverity.WARNING
            holder.newAnnotation(severity, issue.message)
                .range(range)
                .create()
        }
    }
}
