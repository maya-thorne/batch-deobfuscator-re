package utils

object RandomVariableGenerator {

    private val lowerLetters = 97..122
    private val upperLetters = 65..90

    private val ranges = listOf(lowerLetters, upperLetters)
    private val existingVariableNames = mutableListOf<String>()

    // [variable name, statement]
    fun generateVariable(value: String) = generateVariableName().let {
        listOf(it, "\"$it=$value\"")
    }

    fun generateVariableName(length: Int = Config.VARIABLE_LENGTH): String {
        var result = ""

        for (i in 1..length) {
            val randomRange = ranges.random()
            result += randomRange.random().toChar()
        }

        if (existingVariableNames.contains(result)) return generateVariableName(length)
        existingVariableNames.add(result)

        return result
    }
}
