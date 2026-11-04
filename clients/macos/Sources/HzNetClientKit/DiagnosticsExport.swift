import Foundation

/// 诊断包导出（#90 / #110）：文件名与 zip 内容是纯函数；写盘后把 mode
/// 收成 0600。保存面板仍由 App 层组合。zip 为 store（不压缩）——诊断内容
/// 是 JSON，压缩收益小，换取零第三方依赖的可测实现。
public enum DiagnosticsExport {
    /// 默认文件名：`hznet-diagnostics-<Node Name>-<yyyyMMdd-HHmmss>.zip`。
    /// Node Name 里的路径不安全字符替换为 `-`。
    public static func defaultFileName(
        nodeName: String,
        now: Date,
        calendar: Calendar = Calendar(identifier: .gregorian)
    ) -> String {
        let safe = nodeName.map { character in
            character.isLetter || character.isNumber ? character : "-"
        }
        let compact = String(safe).replacingOccurrences(of: "--+", with: "-", options: .regularExpression)
            .trimmingCharacters(in: CharacterSet(charactersIn: "-"))
        let node = compact.isEmpty ? "node" : compact
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        formatter.timeZone = .current
        return "hznet-diagnostics-\(node)-\(formatter.string(from: now)).zip"
    }

    /// 诊断包内容：diagnostics.json（App 不另行读取日志，#90 验收）。
    public static func makeArchive(report: DiagnosticsReport) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let json = try encoder.encode(report)
        var writer = ZipWriter()
        writer.add(name: "diagnostics.json", data: json)
        // 归档 mtime 是导出时刻（诊断内容的时点在 JSON 的 status 里）。
        return try writer.finish(date: Date())
    }

    /// 写出 zip，再把权限收成仅属主可读写（0600）。`Data.write` 沿用
    /// 已有文件的 mode 或进程 umask（保存面板默认往往是 0644），与 CLI
    /// `hz diagnostics -o` 的 OpenOptions `.mode(0o600)` 对齐必须在写完后
    /// 再设一次（#110）。不改 zip 字节。
    public static func writeArchive(_ data: Data, to url: URL) throws {
        try data.write(to: url)
        try FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }
}

/// store-only zip 写入器（#90）：PKZIP 结构（local file header + central
/// directory + EOCD），method 0（不压缩），CRC-32 IEEE。可测：结构字段
/// 与 `unzip -t` 兼容。
public struct ZipWriter {
    private struct Entry {
        let name: String
        let data: Data
        let crc32: UInt32
        let offset: UInt32
    }

    private var entries: [Entry] = []
    private var offset: UInt32 = 0

    public init() {}

    public mutating func add(name: String, data: Data) {
        entries.append(
            Entry(name: name, data: data, crc32: crc32(data), offset: offset)
        )
        // local header（30 + 名字）+ 数据。
        offset += 30 + UInt32(name.utf8.count) + UInt32(data.count)
    }

    /// 组装完整 zip 字节；date 取 mtime（DOS 时间）。
    public func finish(date: Date) throws -> Data {
        guard !entries.isEmpty else {
            throw DiagnosticsExportError.emptyArchive
        }
        var out = Data()
        let dosDate = dosDateTime(date)
        for entry in entries {
            // ---- local file header ----
            out.appendLE(UInt32(0x04034B50))
            out.appendLE(UInt16(20))          // version needed
            out.appendLE(UInt16(1 << 11))     // UTF-8 名字
            out.appendLE(UInt16(0))           // method 0 = store
            out.appendLE(dosDate.0)           // mod time
            out.appendLE(dosDate.1)           // mod date
            out.appendLE(entry.crc32)
            out.appendLE(UInt32(entry.data.count))        // compressed
            out.appendLE(UInt32(entry.data.count))        // uncompressed
            out.appendLE(UInt16(entry.name.utf8.count))
            out.appendLE(UInt16(0))           // extra len
            out.append(entry.name.data(using: .utf8)!)
            out.append(entry.data)
        }
        let centralStart = UInt32(out.count)
        for entry in entries {
            // ---- central directory header ----
            out.appendLE(UInt32(0x02014B50))
            out.appendLE(UInt16(20))          // version made by
            out.appendLE(UInt16(20))          // version needed
            out.appendLE(UInt16(1 << 11))
            out.appendLE(UInt16(0))
            out.appendLE(dosDate.0)
            out.appendLE(dosDate.1)
            out.appendLE(entry.crc32)
            out.appendLE(UInt32(entry.data.count))
            out.appendLE(UInt32(entry.data.count))
            out.appendLE(UInt16(entry.name.utf8.count))
            out.appendLE(UInt16(0))           // extra
            out.appendLE(UInt16(0))           // comment
            out.appendLE(UInt16(0))           // disk
            out.appendLE(UInt16(0))           // internal attrs
            out.appendLE(UInt32(0))           // external attrs
            out.appendLE(entry.offset)
            out.append(entry.name.data(using: .utf8)!)
        }
        let centralSize = UInt32(out.count) - centralStart
        // ---- EOCD ----
        out.appendLE(UInt32(0x06054B50))
        out.appendLE(UInt16(0))
        out.appendLE(UInt16(0))
        out.appendLE(UInt16(entries.count))
        out.appendLE(UInt16(entries.count))
        out.appendLE(centralSize)
        out.appendLE(centralStart)
        out.appendLE(UInt16(0))
        return out
    }

    /// DOS 时间（2 秒粒度）：早于 1980 的日期 clamp 到 1980（zip 下限）。
    func dosDateTime(_ date: Date) -> (UInt16, UInt16) {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = .current
        let parts = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let year = max(Int(parts.year ?? 1980), 1980)
        let time = UInt16(
            ((parts.hour ?? 0) << 11) | ((parts.minute ?? 0) << 5) | ((parts.second ?? 0) / 2)
        )
        let day = UInt16(
            ((year - 1980) << 9) | ((parts.month ?? 1) << 5) | (parts.day ?? 1)
        )
        return (time, day)
    }

    /// CRC-32 IEEE（zip / gzip 同一多项式），逐位实现（表可省）。
    func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                let mask: UInt32 = (crc & 1) != 0 ? 0xEDB8_8320 : 0
                crc = (crc >> 1) ^ mask
            }
        }
        return ~crc
    }
}

public enum DiagnosticsExportError: Error, Equatable {
    case emptyArchive
}

extension Data {
    mutating func appendLE(_ value: UInt16) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
    }

    mutating func appendLE(_ value: UInt32) {
        append(UInt8(value & 0xFF))
        append(UInt8((value >> 8) & 0xFF))
        append(UInt8((value >> 16) & 0xFF))
        append(UInt8((value >> 24) & 0xFF))
    }
}
