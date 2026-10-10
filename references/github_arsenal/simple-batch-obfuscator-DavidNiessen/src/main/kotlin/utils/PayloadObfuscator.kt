package utils

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

object PayloadObfuscator {

    private fun String.toUTF16ByteArray() = this.toByteArray(Charsets.UTF_16LE)

    @OptIn(ExperimentalEncodingApi::class)
    private fun ByteArray.encodeToBase64String() = Base64.Default.encode(this)


    fun asPowershellCommand(
        payload: String,
        encode: Boolean = false,
    ): String {
        val powershellCommand = "powershell.exe"
        if (encode)
            return "$powershellCommand -EncodedCommand ${payload.toUTF16ByteArray().encodeToBase64String()}"

        return "$powershellCommand $payload"
    }

}
