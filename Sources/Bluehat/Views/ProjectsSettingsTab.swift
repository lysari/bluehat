import AppKit
import BluehatCore
import SwiftUI

struct ProjectsSettingsTab: View {
    let settings: SettingsStore

    var body: some View {
        Form {
            Section {
                if settings.projectFolders.isEmpty {
                    ContentUnavailableView("No Project Folders", systemImage: "folder", description: Text("Add the folders where you keep code so Bluehat can check their npm packages and config files."))
                } else {
                    ForEach(settings.projectFolders, id: \.self) { folder in
                        let name = NSString(string: folder).abbreviatingWithTildeInPath
                        HStack(spacing: Metrics.spaceMedium) {
                            Image(systemName: "folder")
                                .foregroundStyle(Palette.secondaryText)
                                .accessibilityHidden(true)
                            Text(name)
                                .font(Typography.body)
                                .lineLimit(1)
                                .truncationMode(.middle)
                                .help(folder)
                            Spacer()
                            Button("Remove") { settings.removeProjectFolder(folder) }
                                .accessibilityLabel("Remove \(name)")
                        }
                    }
                }
            } header: {
                Text("Project folders")
            } footer: {
                Text("Bluehat looks up to \(ProjectFolders.maxDepth) folders deep in each for npm projects, checks their lockfiles against known malicious package versions, and checks config files and install scripts for hidden code. It only reads files and skips node_modules, .git, build output and symlinked folders. Add any other folder where you keep code.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            Section {
                Button("Add Folder…", action: chooseFolders)
            }
        }
        .formStyle(.grouped)
    }

    private func chooseFolders() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = true
        panel.prompt = "Add"
        panel.message = "Choose folders where you keep code projects."
        guard panel.runModal() == .OK else { return }
        for url in panel.urls {
            settings.addProjectFolder(url.path)
        }
    }
}
