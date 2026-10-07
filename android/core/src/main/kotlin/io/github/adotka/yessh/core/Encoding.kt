package io.github.adotka.yessh.core

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.Base64

internal val secureRandom = SecureRandom()

fun randomBytes(n: Int): ByteArray = ByteArray(n).also { secureRandom.nextBytes(it) }

object B64 {
    private val std = Base64.getEncoder()
    private val stdDec = Base64.getDecoder()
    private val url = Base64.getUrlEncoder().withoutPadding()
    private val urlDec = Base64.getUrlDecoder()

    fun encode(b: ByteArray): String = std.encodeToString(b)
    fun decode(s: String): ByteArray = stdDec.decode(s)
    fun urlEncode(b: ByteArray): String = url.encodeToString(b)

    /** base64url without padding; also accepts padding and the standard alphabet. */
    fun urlDecode(s: String): ByteArray {
        val t = s.trimEnd('=').replace('+', '-').replace('/', '_')
        require(t.all { it.isLetterOrDigit() && it.code < 128 || it == '-' || it == '_' }) { "invalid base64url" }
        return urlDec.decode(t)
    }
}

/** RFC 4648 base32, lowercase, no padding. */
fun base32(bytes: ByteArray): String {
    val alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    val sb = StringBuilder()
    var acc = 0
    var bits = 0
    for (b in bytes) {
        acc = (acc shl 8) or (b.toInt() and 0xff)
        bits += 8
        while (bits >= 5) {
            sb.append(alphabet[(acc ushr (bits - 5)) and 31])
            bits -= 5
        }
    }
    if (bits > 0) sb.append(alphabet[(acc shl (5 - bits)) and 31])
    return sb.toString()
}

fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

fun hexBytes(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }

/** RFC 4251 wire encoding. */
class SshWriter {
    private val out = ByteArrayOutputStream()

    fun u32(v: Long): SshWriter {
        require(v in 0..0xffffffffL) { "uint32 out of range" }
        out.write(ByteBuffer.allocate(4).putInt(v.toInt()).array())
        return this
    }

    fun u64(v: Long): SshWriter {
        require(v >= 0) { "uint64 out of range" }
        out.write(ByteBuffer.allocate(8).putLong(v).array())
        return this
    }

    fun string(b: ByteArray): SshWriter {
        u32(b.size.toLong())
        out.write(b)
        return this
    }

    fun string(s: String): SshWriter = string(s.toByteArray(Charsets.UTF_8))

    fun raw(b: ByteArray): SshWriter {
        out.write(b)
        return this
    }

    fun bytes(): ByteArray = out.toByteArray()
}

class SshReader(private val buf: ByteArray) {
    var off = 0
        private set

    private fun need(n: Int) {
        if (n < 0 || off + n > buf.size) throw IllegalArgumentException("ssh wire: truncated")
    }

    fun u32(): Long {
        need(4)
        val v = ByteBuffer.wrap(buf, off, 4).int.toLong() and 0xffffffffL
        off += 4
        return v
    }

    fun u64(): Long {
        need(8)
        val v = ByteBuffer.wrap(buf, off, 8).long
        off += 8
        if (v < 0) throw IllegalArgumentException("ssh wire: uint64 too large")
        return v
    }

    fun bytes(): ByteArray {
        val n = u32()
        if (n > Int.MAX_VALUE) throw IllegalArgumentException("ssh wire: string too long")
        need(n.toInt())
        val v = buf.copyOfRange(off, off + n.toInt())
        off += n.toInt()
        return v
    }

    fun str(): String = String(bytes(), Charsets.UTF_8)

    val done: Boolean get() = off == buf.size

    fun end() {
        if (!done) throw IllegalArgumentException("ssh wire: trailing data")
    }
}

/** Unsigned big-endian magnitude -> RFC 4251 mpint body: strip leading zeros, prepend 0x00 if the top bit is set. */
fun mpint(magnitude: ByteArray): ByteArray {
    var i = 0
    while (i < magnitude.size && magnitude[i] == 0.toByte()) i++
    val m = magnitude.copyOfRange(i, magnitude.size)
    return if (m.isNotEmpty() && (m[0].toInt() and 0x80) != 0) byteArrayOf(0) + m else m
}

/** Unsigned value -> fixed-width big-endian bytes. */
internal fun BigInteger.toFixed(len: Int): ByteArray {
    val b = toByteArray()
    return when {
        b.size == len -> b
        b.size == len + 1 && b[0] == 0.toByte() -> b.copyOfRange(1, b.size)
        b.size < len -> ByteArray(len - b.size) + b
        else -> throw IllegalArgumentException("value too large")
    }
}
