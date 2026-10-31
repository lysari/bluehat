import Foundation
import Testing
@testable import BluehatCore

struct TerminalCommandTests {
    let root = FileManager.default.temporaryDirectory.appending(path: "bluehat-command-\(UUID().uuidString)")

    func zsh(_ arguments: [String], input: String) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/zsh")
        process.arguments = ["-f"] + arguments
        let stdin = Pipe()
        let stdout = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = FileHandle.nullDevice
        try process.run()
        try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8))
        try stdin.fileHandleForWriting.close()
        let output = stdout.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: output, as: UTF8.self)
    }

    func runScript(_ command: TerminalCommand, input: String) throws -> (output: String, directory: URL) {
        let directory = root.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let script = directory.appending(path: "Bluehat.command")
        try Data(command.script.utf8).write(to: script)
        return (try zsh([script.path], input: input), directory)
    }

    @Test(arguments: ["18.20.1", "a'b", "'; print -r -- injected; '", "$(id) `id` ${HOME} \\ \" ~ * ?", ""])
    func quotesEveryValueSoTheShellSeesItLiterally(value: String) throws {
        let echoed = try zsh(["-c", "print -r -- " + TerminalCommand.quoted(value)], input: "")

        #expect(echoed == value + "\n")
    }

    @Test func quotesOnlyTheValuesAfterTheFixedCommand() {
        let command = TerminalCommand(setup: nil, command: "asdf install", values: ["nodejs", "it's"])

        #expect(command.text == #"asdf install 'nodejs' 'it'\''s'"#)
    }

    @Test func scriptShowsTheCommandAndRunsItOnlyAfterReturn() throws {
        let command = TerminalCommand(setup: "export NVM_DIR=x", command: "nvm install", values: ["18.20.1"])
        let lines = command.script.split(separator: "\n").map(String.init)
        let prompt = try #require(lines.firstIndex { $0.hasPrefix("read -r ") })

        #expect(lines.first == "#!/bin/zsh")
        #expect(lines.contains(#"print -r -- '    nvm install '\''18.20.1'\'''"#))
        #expect(lines[prompt].hasSuffix("|| exit 1"))
        #expect(lines.firstIndex(of: "export NVM_DIR=x") == prompt + 1)
        #expect(lines.firstIndex(of: "nvm install '18.20.1'") == prompt + 2)
        #expect(lines.filter { $0.contains("nvm install") }.count == 2)
    }

    @Test func scriptRunsTheCommandOnReturnAndNotOnEndOfInput() throws {
        defer { try? FileManager.default.removeItem(at: root) }
        let marker = root.appending(path: "ran").path
        let command = TerminalCommand(setup: nil, command: "touch", values: [marker])

        let cancelled = try runScript(command, input: "")
        #expect(cancelled.output.contains("    touch '\(marker)'"))
        #expect(!FileManager.default.fileExists(atPath: marker))
        #expect(!FileManager.default.fileExists(atPath: cancelled.directory.path))

        _ = try runScript(command, input: "\n")
        #expect(FileManager.default.fileExists(atPath: marker))
    }
}
