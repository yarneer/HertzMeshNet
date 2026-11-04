package dev.hznet.android

import dev.hznet.android.update.UpdateCheck
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** #102：版本比较与 sha256 校验（纯逻辑，host 单测）。 */
class UpdateCheckTest {

    @Test
    fun semverCompareFlagsOnlyStrictlyNewer() {
        assertTrue(UpdateCheck.isNewer("0.3.0", "0.4.0"))
        assertTrue(UpdateCheck.isNewer("0.4.0", "0.4.1"))
        assertTrue(UpdateCheck.isNewer("0.4.9", "1.0.0"))
        assertFalse(UpdateCheck.isNewer("0.4.0", "0.4.0"))
        assertFalse(UpdateCheck.isNewer("0.4.1", "0.4.0"))
        assertFalse("非数字段按 0 处理，不算更高", UpdateCheck.isNewer("0.4.0", "0.4.0-dev1"))
    }

    @Test
    fun manifestParsingAndApkEntry() {
        val manifest = UpdateCheck.parseManifest(
            """{"version":"0.4.1","files":{
                "linux-x86_64/hzd":{"sha256":"aa","size":10},
                "android-arm64/hznet.apk":{"sha256":"BB00","size":2048}
            }}"""
        )
        assertNotNull(manifest)
        assertEquals("0.4.1", manifest!!.version)
        val apk = UpdateCheck.apkEntry(manifest)
        assertEquals("android-arm64/hznet.apk", apk?.path)
        assertEquals(2048L, apk?.size)
        assertNull(UpdateCheck.parseManifest("not json"))
        assertNull(UpdateCheck.parseManifest("""{"version":"1"}"""))
    }

    @Test
    fun sha256Verification() {
        // "hznet" 的 sha256。
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest("hznet".toByteArray())
        val hex = digest.joinToString("") { "%02x".format(it) }
        assertTrue(UpdateCheck.sha256Matches("hznet".toByteArray(), hex))
        assertTrue(UpdateCheck.sha256Matches("hznet".toByteArray(), hex.uppercase()))
        assertFalse(UpdateCheck.sha256Matches("hzneT".toByteArray(), hex))
        assertFalse(UpdateCheck.sha256Matches("other".toByteArray(), hex))
    }
}
