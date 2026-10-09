package io.github.adotka.yessh.core

import org.junit.Test
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The app's licenses screen ships copies of license texts; keep them in sync with the repo. */
class LicenseFilesTest {
    private val raw = File(repoRoot, "android/app/src/main/res/raw")

    @Test
    fun appUnlicenseMatchesRepoLicense() {
        assertEquals(File(repoRoot, "LICENSE").readText(), File(raw, "unlicense.txt").readText())
    }

    @Test
    fun apacheLicenseIsComplete() {
        val text = File(raw, "apache_2_0.txt").readText()
        assertTrue(text.startsWith("Apache License\nVersion 2.0, January 2004"))
        assertTrue("END OF TERMS AND CONDITIONS" in text)
    }
}
