import AppKit
import BluehatCore
import SwiftUI

struct DeepScanExclusionsSection: View {
    private static let lastRowID = "addFolder"

    let settings: SettingsStore
    let scroller: ScrollViewProxy
    @State private var patternText = ""
    @State private var problem: ExclusionPattern.Problem?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Section {
            ForEach(settings.excludedFolders, id: \.self) { folder in
                row(folder, isPattern: false) { settings.removeExcludedFolder(folder) }
            }
            ForEach(settings.excludedPatterns, id: \.self) { pattern in
                row(pattern, isPattern: true) { settings.removeExcludedPattern(pattern) }
            }
            HStack(spacing: Metrics.spaceMedium) {
                TextField("Exclude pattern", text: $patternText, prompt: Text("Pattern, like node_modules"))
                    .font(Typography.detail)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .autocorrectionDisabled()
                    .onSubmit(addPattern)
                    .onChange(of: patternText) { problem = nil }
                Button("Add", action: addPattern)
            }
            if let problem {
                Text(problem.message)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
            }
            Button("Add Folder…", action: chooseFolders)
                .id(Self.lastRowID)
        } header: {
            Text("Deep Scan exclusions")
        } footer: {
            Text("A Deep Scan's walk of the disk skips these and names them at the top of its Not Scanned tab. Patterns use .gitignore globs and ignore case, like `node_modules`, `*.log`, `build/` or `**` across folders. One starting with `/` or `~`, like `~/Library/Caches`, applies only at that path. Any other matches at any depth, even `src/generated`, which .gitignore would tie to one folder.")
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
        }
        .animation(Motion.standard, value: problem)
        .animation(Motion.standard, value: settings.excludedFolders)
        .animation(Motion.standard, value: settings.excludedPatterns)
    }

    private func row(_ entry: String, isPattern: Bool, remove: @escaping () -> Void) -> some View {
        let name = NSString(string: entry).abbreviatingWithTildeInPath
        return HStack(spacing: Metrics.spaceMedium) {
            Image(systemName: isPattern ? "asterisk" : "folder")
                .foregroundStyle(Palette.secondaryText)
                .accessibilityHidden(true)
            Text(name)
                .font(isPattern ? Typography.detail : Typography.body)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(entry)
            Spacer()
            Button("Remove", action: remove)
                .accessibilityLabel("Remove \(name)")
        }
    }

    private func addPattern() {
        do {
            try settings.addExcludedPattern(patternText)
            patternText = ""
            problem = nil
            revealLastRow()
        } catch {
            show(error)
        }
    }

    private func revealLastRow() {
        withAnimation(reduceMotion ? nil : Motion.standard) { scroller.scrollTo(Self.lastRowID) }
    }

    private func chooseFolders() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Exclude"
        panel.message = "Choose folders a Deep Scan should skip."
        guard panel.runModal() == .OK else { return }
        problem = nil
        for url in panel.urls {
            do {
                try settings.addExcludedFolder(url.path)
            } catch {
                show(error)
            }
        }
        revealLastRow()
    }

    private func show(_ refusal: ExclusionPattern.Problem) {
        problem = refusal
        AccessibilityNotification.Announcement(refusal.message).post()
        revealLastRow()
    }
}
