package xyz.zivoralabs.toolip

import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.options.ConfigurationException
import java.awt.BorderLayout
import java.nio.file.Files
import java.nio.file.Path
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField

/**
 * Settings are stored in the application-wide PropertiesComponent rather
 * than project code. An untrusted repository cannot activate the analyzer.
 */
class ToolipSettings : Configurable {
    private var field: JTextField? = null
    private var consent: JCheckBox? = null

    override fun getDisplayName(): String = "Toolip Security"

    override fun createComponent(): JComponent {
        val input = JTextField(50)
        val enabled = JCheckBox(
            "Enable the local read-only Toolip analyzer for trusted projects"
        )
        field = input
        consent = enabled
        reset()
        return JPanel(BorderLayout(0, 8)).apply {
            add(JLabel("Separately installed Toolip executable (absolute path):"),
                BorderLayout.NORTH)
            add(input, BorderLayout.CENTER)
            add(enabled, BorderLayout.SOUTH)
        }
    }

    override fun isModified(): Boolean {
        val settings = PropertiesComponent.getInstance()
        return field?.text != (settings.getValue("toolip.executablePath") ?: "") ||
            consent?.isSelected != settings.getBoolean("toolip.enabled", false)
    }

    override fun apply() {
        val entered = field?.text?.trim() ?: return
        val enabled = consent?.isSelected ?: false
        if (enabled && entered.isEmpty())
            throw ConfigurationException(
                "Choose a trusted local Toolip executable before enabling analysis."
            )
        if (entered.isNotEmpty()) {
            val candidate = runCatching { Path.of(entered) }.getOrNull()
                ?: throw ConfigurationException("Invalid executable path.")
            if (!candidate.isAbsolute || Files.isSymbolicLink(candidate) ||
                !Files.isRegularFile(candidate) ||
                !Files.isExecutable(candidate))
                throw ConfigurationException(
                    "Toolip must be an absolute, regular, executable, non-symlink file."
                )
        }
        PropertiesComponent.getInstance().apply {
            setValue("toolip.executablePath", entered)
            setValue("toolip.enabled", enabled, false)
        }
    }

    override fun reset() {
        val settings = PropertiesComponent.getInstance()
        field?.text = settings.getValue("toolip.executablePath") ?: ""
        consent?.isSelected = settings.getBoolean("toolip.enabled", false)
    }

    override fun disposeUIResources() {
        field = null
        consent = null
    }
}
