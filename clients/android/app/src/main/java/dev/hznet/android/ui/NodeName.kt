package dev.hznet.android.ui

/**
 * Node Name 规范化（规格 §6）：`Build.MODEL` 预填值的推导——小写、非字母
 * 数字转 `-`、去首尾 `-`（如 "Pixel 8" → "pixel-8"）。纯函数，host 单测；
 * 重名消歧沿用 coord 现有规则。
 */
object NodeName {
    fun fromModel(model: String?): String {
        val cleaned = (model ?: "")
            .trim()
            .lowercase()
            .map { ch -> if (ch.isLetterOrDigit()) ch else '-' }
            .joinToString("")
        // 压缩连续 '-' 并去首尾。
        return cleaned.split('-').filter { it.isNotEmpty() }.joinToString("-")
    }
}
