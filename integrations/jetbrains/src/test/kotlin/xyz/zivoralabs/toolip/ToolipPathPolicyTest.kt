package xyz.zivoralabs.toolip

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFalse

class ToolipPathPolicyTest {
    @Test
    fun projectOwnedExecutablesAndRelativeCommandsCannotBecomeAnalyzer() {
        val fixture = Files.createTempDirectory("toolip-jetbrains-trust")
        try {
            val project = Files.createDirectory(fixture.resolve("workspace"))
            val inside = project.resolve("toolip")
            val outside = fixture.resolve("toolip-external")
            Files.writeString(inside, "inert fixture, never executed")
            Files.writeString(outside, "inert fixture, never executed")
            inside.toFile().setExecutable(true)
            outside.toFile().setExecutable(true)

            assertNull(ToolipPathPolicy.trustedExecutable(
                inside.toString(), project
            ))
            assertNull(ToolipPathPolicy.trustedExecutable(
                "toolip", project
            ))
            assertNull(ToolipPathPolicy.trustedExecutable(
                null, project
            ))
            if (Files.isExecutable(outside)) {
                assertEquals(
                    outside.toRealPath(),
                    ToolipPathPolicy.trustedExecutable(
                        outside.toString(), project
                    )
                )
            }
            val cwd = ToolipPathPolicy.separateWorkingDirectory(project)
            assertNotNull(cwd)
            assertFalse(cwd.startsWith(project.toRealPath()))
        } finally {
            fixture.toFile().deleteRecursively()
        }
    }

    @Test
    fun symlinkedToolingAndProjectDirectoryAliasesStayRejected() {
        val fixture = Files.createTempDirectory("toolip-jetbrains-link")
        try {
            val project = Files.createDirectory(fixture.resolve("project"))
            val inside = project.resolve("toolip")
            Files.writeString(inside, "inert fixture")
            inside.toFile().setExecutable(true)
            val alias = fixture.resolve("alias")
            val binaryLink = fixture.resolve("binary-link")
            val linked = runCatching {
                Files.createSymbolicLink(alias, project)
                Files.createSymbolicLink(binaryLink, inside)
            }.isSuccess
            if (linked) {
                assertNull(ToolipPathPolicy.trustedExecutable(
                    inside.toString(), alias
                ))
                assertNull(ToolipPathPolicy.trustedExecutable(
                    binaryLink.toString(), project
                ))
            }
        } finally {
            fixture.toFile().deleteRecursively()
        }
    }
}
