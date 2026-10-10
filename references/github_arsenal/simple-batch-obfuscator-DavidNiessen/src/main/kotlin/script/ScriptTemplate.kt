package script

class ScriptTemplate(
    private val variableNames: List<String>,
    private val leadingLines: List<String> = emptyList(),
    private val trailingLines: List<String> = emptyList(),
) {

    fun writeAsString(): String {
        var result = ""
        val lines = mutableListOf<String>().apply {
            addAll(leadingLines)
            add(variableNames.map { "%$it%" }.joinToString(""))
            addAll(trailingLines)
        }

        lines.forEach { result += "$it\n" }

        return result
    }

}
