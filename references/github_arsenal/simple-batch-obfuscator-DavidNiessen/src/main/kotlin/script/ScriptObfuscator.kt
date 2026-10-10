package script

import Config
import utils.CommandUtils
import utils.PayloadObfuscator
import utils.RandomVariableGenerator

object ScriptObfuscator {

    fun obfuscate(command: String): ScriptTemplate {
        var payload = command
        if (Config.powerShellSettings.runAsPowershell) {
            payload = PayloadObfuscator.asPowershellCommand(payload, Config.powerShellSettings.encode)
        }

        val (orderedNames, statements) = CommandUtils.chunkAndRandomize(payload)

        val setCommand = generateSetCommand()
        val setVariableName = setCommand.variableName

        val leadingLines = mutableListOf<String>().apply {
            add("@echo off")
            add(generateDelayedExecutionString())
            addAll(setCommand.lines)
            addAll(statements.map { "!$setVariableName! $it" })
        }

        return ScriptTemplate(
            leadingLines = leadingLines,
            variableNames = orderedNames,
        )
    }

    private fun generateDelayedExecutionString(): String {
        val command = "setlocal enabledelayedexpansion"
        var result = ""

        command.forEach {
            result += "%${RandomVariableGenerator.generateVariableName()}%$it%${
                RandomVariableGenerator.generateVariableName()
            }%"
        }

        return result
    }

    private fun generateSetCommand(): SetCommand {
        val variableName = RandomVariableGenerator.generateVariableName()
        val (nameS, statementS) = RandomVariableGenerator.generateVariable("s")
        val (nameT, statementT) = RandomVariableGenerator.generateVariable("t")
        return SetCommand(
            listOf(
                "set $statementS",
                "set $statementT",
                "set \"$variableName=!$nameS!e!$nameT!\"",
            ),
            variableName
        )
    }

    private data class SetCommand(
        val lines: List<String>,
        val variableName: String,
    )
}
