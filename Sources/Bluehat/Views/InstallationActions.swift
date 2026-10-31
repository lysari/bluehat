import AppKit
import BluehatCore
import SwiftUI

struct InstallationActions: View {
    private struct Plan: Equatable {
        let installation: Installation
        let target: SoftwareVersion?
        let update: TerminalCommand?
        let remove: TerminalCommand?
    }

    private static let terminalApp = URL(fileURLWithPath: "/System/Applications/Utilities/Terminal.app")
    private static let scriptName = "Bluehat.command"
    private static let privatePermissions = 0o700

    let path: String
    let store: ScanStore
    let onMovedToTrash: () -> Void
    @State private var plan: Plan?
    @State private var hasLookedUp = false
    @State private var isConfirmingTrash = false
    @State private var problem: String?
    @Environment(\.openURL) private var openURL

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            if let plan {
                buttons(for: plan)
                notes(for: plan)
            } else if hasLookedUp {
                caption("Bluehat no longer finds this copy where the scan saw it. Scan again.")
            }
            if let problem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .task(id: path) {
            plan = currentPlan()
            hasLookedUp = true
        }
        .confirmationDialog("Move this copy to the Trash?", isPresented: $isConfirmingTrash, titleVisibility: .visible) {
            Button("Move to Trash", role: .destructive, action: moveToTrash)
        } message: {
            Text("Bluehat will move \(path) to the Trash. You can put it back from the Trash until you empty it.")
        }
    }

    private func buttons(for plan: Plan) -> some View {
        HStack(spacing: Metrics.spaceMedium) {
            if let page = plan.installation.downloadPage {
                Button("Download Page", systemImage: "arrow.up.right.square") { openURL(page) }
                    .help(page.absoluteString)
            } else {
                Button("Update…", systemImage: "arrow.up.circle") { runInTerminal(\.update) }
                    .disabled(plan.update == nil)
            }
            if plan.installation.isTrashable {
                Button("Move to Trash…", systemImage: "trash") { isConfirmingTrash = true }
            } else if plan.remove != nil {
                Button("Remove…", systemImage: "trash") { runInTerminal(\.remove) }
            }
        }
        .buttonStyle(.bordered)
        .controlSize(.small)
    }

    @ViewBuilder
    private func notes(for plan: Plan) -> some View {
        if let page = plan.installation.downloadPage {
            caption("Download the current release from \(page.host() ?? page.absoluteString) and run its installer.")
        } else if let target = plan.target, plan.update != nil {
            caption("\(target) fixes every advisory Bluehat found on this copy.")
        } else if plan.target == nil {
            caption("No fixed release covers every advisory on this copy, so there is no version to update to. Move to a newer supported release line.")
        } else {
            caption("Bluehat can't build a safe update command for this copy.")
        }
        if plan.update != nil || plan.remove != nil {
            caption("Terminal shows the command and runs it only after you press Return.")
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: Metrics.spaceSmall, verticalSpacing: Metrics.spaceTight) {
                if let update = plan.update {
                    commandRow("Update", update)
                }
                if let remove = plan.remove {
                    commandRow("Remove", remove)
                }
            }
        }
        if !plan.installation.isTrashable, plan.remove == nil {
            caption("Removing this copy needs administrator rights, so Bluehat leaves it to you.")
        }
    }

    private func commandRow(_ title: String, _ command: TerminalCommand) -> some View {
        GridRow {
            Text(title)
                .font(Typography.captionEmphasis)
                .foregroundStyle(Palette.secondaryText)
            Text(command.text)
                .font(Typography.detail)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func caption(_ text: String) -> some View {
        Text(text)
            .font(Typography.caption)
            .foregroundStyle(Palette.secondaryText)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func currentPlan() -> Plan? {
        let installs = Scanner.installedSoftware()
        guard let installation = Scanner.installation(at: path, in: installs) else { return nil }
        let target = installation.updateTarget(findings: store.findings)
        return Plan(installation: installation, target: target, update: target.flatMap(installation.updateCommand), remove: installation.removeCommand(among: installs))
    }

    private func runInTerminal(_ command: KeyPath<Plan, TerminalCommand?>) {
        let shown = plan
        plan = currentPlan()
        guard let plan, plan == shown, let selected = plan[keyPath: command] else {
            problem = ScanStore.InstallationError.changedSinceScan.localizedDescription
            return
        }
        Task {
            do {
                try await openInTerminal(selected)
                problem = nil
            } catch {
                problem = "Couldn't open Terminal: \(error.localizedDescription)"
            }
        }
    }

    private func openInTerminal(_ command: TerminalCommand) async throws {
        let fileManager = FileManager.default
        let directory = fileManager.temporaryDirectory.appending(path: "Bluehat-\(UUID().uuidString)", directoryHint: .isDirectory)
        try fileManager.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: Self.privatePermissions])
        let script = directory.appending(path: Self.scriptName)
        guard fileManager.createFile(atPath: script.path, contents: Data(command.script.utf8), attributes: [.posixPermissions: Self.privatePermissions]) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: script.path])
        }
        _ = try await NSWorkspace.shared.open([script], withApplicationAt: Self.terminalApp, configuration: NSWorkspace.OpenConfiguration())
    }

    private func moveToTrash() {
        guard let installation = plan?.installation else { return }
        do {
            try store.moveToTrash(installation)
            onMovedToTrash()
        } catch {
            problem = error.localizedDescription
        }
    }
}
