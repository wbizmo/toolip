package xyz.zivoralabs.toolip

import com.intellij.ide.util.PropertiesComponent
import com.intellij.openapi.options.Configurable
import java.awt.BorderLayout
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JTextField

/** Operator-owned binary configuration; the plugin never downloads or
 * executes a Toolip binary merely because an untrusted project asks for one.
 */
class ToolipSettings : Configurable {
    private var field: JTextField? = null

    override fun getDisplayName(): String = "Toolip Security"

    override fun createComponent(): JComponent {
        val input = JTextField(50)
        field = input
        reset()
        return JPanel(BorderLayout(0, 8)).apply {
            add(JLabel("Trusted Toolip executable (absolute path):"), BorderLayout.NORTH)
            add(input, BorderLayout.CENTER)
        }
    }

    override fun isModified(): Boolean =
        field?.text != (PropertiesComponent.getInstance()
            .getValue("toolip.executablePath") ?: "")

    override fun apply() {
        val entered = field?.text?.trim() ?: return
        if (entered.isNotEmpty() && !java.nio.file.Path.of(entered).isAbsolute)
            throw com.intellij.openapi.options.ConfigurationException(
                "Toolip executable must be an absolute path."
            )
        PropertiesComponent.getInstance().setValue(
            "toolip.executablePath", entered
        )
    }

    override fun reset() {
        field?.text = PropertiesComponent.getInstance()
            .getValue("toolip.executablePath") ?: ""
    }

    override fun disposeUIResources() {
        field = null
    }
}
