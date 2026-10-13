package utils

object CommandUtils {

    fun chunkAndRandomize(command: String): Commands {
        val chunks = chunkCommand(command)
        return randomizeOrder(chunks)
    }

    private fun chunkCommand(command: String): List<String> {
        val length = command.length

        val charsPerVariable: Int = when {
            (length >= 1000) -> 15
            (length >= 500) -> 10
            (length >= 250) -> 6
            (length >= 100) -> 4
            (length >= 50) -> 2
            else -> 1
        }

        return command.chunked(charsPerVariable)
    }

    private fun randomizeOrder(chunks: List<String>): Commands {
        val variables = chunks.map { RandomVariableGenerator.generateVariable(it) }
        val orderedNames = variables.map { it[0] }
        val randomizedStatements = variables.map { it[1] }.shuffled()

        return Commands(orderedNames, randomizedStatements)
    }

    data class Commands(
        val orderedNames: List<String>,
        val statements: List<String>,
    )
}
