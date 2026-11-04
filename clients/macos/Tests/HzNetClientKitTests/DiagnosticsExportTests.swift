import Foundation

@testable import HzNetClientKit

/// #90：诊断包文件名与 store-zip 结构（unzip 兼容）。
struct DiagnosticsExportTests {
    func testDefaultFileName() {
        let date = Date(timeIntervalSince1970: 1_780_000_000) // 2026-06-01（UTC−4 约下午）
        let name = DiagnosticsExport.defaultFileName(nodeName: "mini", now: date)
        hzExpect(name.hasPrefix("hznet-diagnostics-mini-"), "\(name)")
        hzExpect(name.hasSuffix(".zip"), "\(name)")
        // 名字里的非法字符替换。
        let weird = DiagnosticsExport.defaultFileName(nodeName: "a/b:c d", now: date)
        hzExpect(!weird.contains("/"), "\(weird)")
        hzExpect(!weird.contains(":"), "\(weird)")
        hzExpect(!weird.contains(" "), "\(weird)")
    }

    func makeReport() -> DiagnosticsReport {
        DiagnosticsReport(
            status: StatusSnapshot(registered: true, name: "mini", desiredState: "up"),
            version: "0.4.0 (a1b2c3d)",
            os: "macos",
            arch: "aarch64",
            netcheck: .string("opaque"),
            logTail: ["line1", "line2"],
            logNote: "最近 2 行",
            schemaVersion: 1,
            collectedAt: "2026-10-29T10:00:01Z"
        )
    }

    func testArchiveContainsSingleJsonEntry() throws {
        let data = try DiagnosticsExport.makeArchive(report: makeReport())
        // EOCD 是文件尾 22 字节：魔数在其开头，之后 disk/cdDisk/两处条目数。
        let eocd = data.suffix(22)
        hzExpect(Array(eocd.prefix(4)) == [0x50, 0x4B, 0x05, 0x06], "EOCD 魔数")
        // 偏移 8..12：盘上条目数与本盘条目数（各 2 字节，各 1）。
        hzExpect(Data(eocd.dropFirst(8).prefix(4)) == Data([0x01, 0x00, 0x01, 0x00]), "总条目与盘上条目各 1")
        // JSON 可从 zip 字节里直接找到（store 未压缩）。
        let raw = String(decoding: data, as: UTF8.self)
        hzExpect(raw.contains("\"logTail\"") || raw.contains("log_tail"), "诊断 JSON 在包内")
        hzExpect(raw.contains("line1"))
    }

    /// unzip -t 兼容性（CI 与本机都有 /usr/bin/unzip）。
    func testUnzipVerifiesArchive() throws {
        let data = try DiagnosticsExport.makeArchive(report: makeReport())
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hznet-zip-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let zip = dir.appendingPathComponent("diag.zip")
        try data.write(to: zip)
        defer { try? FileManager.default.removeItem(at: dir) }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-t", zip.path]
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        process.waitUntilExit()
        hzExpect(process.terminationStatus == 0, "unzip -t 应通过")
        let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        hzExpect(output.contains("diagnostics.json"), "\(output)")
        hzExpect(output.contains("OK"), "\(output)")
    }

    func testCrc32KnownVector() {
        // "123456789" 的 CRC-32 IEEE = 0xCBF43926（标准测试向量）。
        var writer = ZipWriter()
        writer.add(name: "x", data: Data("123456789".utf8))
        let reference = writer.crc32(Data("123456789".utf8))
        hzExpect(reference == 0xCBF4_3926)
    }

    /// #110：已有 0644（保存面板 / umask）时，写完必须收成 0600。
    /// `Data.write` 覆盖已有文件会保留原 mode，所以这一例在缺 chmod 时失败。
    func testWriteArchiveTightensToOwnerOnly() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("hznet-mode-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let zip = dir.appendingPathComponent("diag.zip")
        let data = try DiagnosticsExport.makeArchive(report: makeReport())
        try data.write(to: zip)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: zip.path)

        try DiagnosticsExport.writeArchive(data, to: zip)

        let attrs = try FileManager.default.attributesOfItem(atPath: zip.path)
        let mode = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? -1
        hzExpect(mode & 0o777 == 0o600, String(format: "mode %04o", mode))
    }

    func testEmptyArchiveThrows() {
        var writer = ZipWriter()
        do {
            _ = try writer.finish(date: Date())
            hzFail("空归档应抛 emptyArchive")
        } catch let error as DiagnosticsExportError {
            hzExpect(error == .emptyArchive)
        } catch {
            hzFail("错误的异常类型：\(error)")
        }
    }
}
