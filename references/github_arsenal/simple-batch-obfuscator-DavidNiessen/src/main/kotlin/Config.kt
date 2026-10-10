object Config {

    const val VARIABLE_LENGTH = 32

    val powerShellSettings = PowerShellSettings()

    data class PowerShellSettings(
        val runAsPowershell: Boolean = true,
        val encode: Boolean = true,
    )

}
