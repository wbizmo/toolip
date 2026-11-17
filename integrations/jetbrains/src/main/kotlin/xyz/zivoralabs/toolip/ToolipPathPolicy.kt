package xyz.zivoralabs.toolip

import java.nio.file.Files
import java.nio.file.Path

/**
 * File-system trust boundary independent of the IntelliJ UI. The operator
 * chooses a globally configured executable; the project may never choose
 * an executable, influence PATH resolution, or supply its working directory.
 */
object ToolipPathPolicy {
    fun trustedExecutable(selected: String?, projectRoot: Path): Path? {
        if (selected.isNullOrBlank() || selected.length > 4096 ||
            selected.contains('\u0000')) return null
        val typed = runCatching { Path.of(selected) }.getOrNull() ?: return null
        if (!typed.isAbsolute || Files.isSymbolicLink(typed)) return null
        val root = runCatching { projectRoot.toRealPath() }.getOrNull()
            ?: return null
        val executable = runCatching { typed.toRealPath() }.getOrNull()
            ?: return null
        if (
            executable.startsWith(root) ||
            !Files.isRegularFile(executable) ||
            !Files.isExecutable(executable)
        ) return null
        return executable
    }

    fun separateWorkingDirectory(projectRoot: Path): Path? {
        val root = runCatching { projectRoot.toRealPath() }.getOrNull()
            ?: return null
        for (candidate in listOf(
            System.getProperty("user.home"),
            System.getProperty("java.io.tmpdir")
        )) {
            if (candidate.isNullOrBlank()) continue
            val resolved = runCatching {
                Path.of(candidate).toRealPath()
            }.getOrNull() ?: continue
            if (Files.isDirectory(resolved) && !resolved.startsWith(root))
                return resolved
        }
        return null
    }
}
