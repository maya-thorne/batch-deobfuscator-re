package utils


fun String.isValidInput(input: String?) = input?.isNotBlank() ?: false

fun String.appendFileExtension(
    input: String,
    fileExtension: String,
): String {
    var fileName = input
    var extension = fileExtension

    if (!extension.startsWith('.'))
        extension = ".$fileExtension"

    if (!fileName.endsWith(extension))
        fileName = "$fileName$extension"

    return fileName
}
