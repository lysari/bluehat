import BluehatCore
import SwiftUI

struct AppUpdateSection: View {
    let store: ScanStore

    private var update: AppUpdateReview {
        store.appUpdate
    }

    var body: some View {
        Section {
            checkRow
            LabeledContent(AppUpdater.trustedKeys.count > 1 ? "Update keys" : "Update key") {
                Text(AppUpdater.trustedKeys.isEmpty ? "Not set in this build" : AppUpdater.trustedKeys.map(RuleFeed.fingerprint(of:)).joined(separator: "\n"))
                    .font(Typography.detail)
                    .textSelection(.enabled)
            }
            switch update.status {
            case .notChecked, .upToDate:
                EmptyView()
            case .failed(let error):
                problemRows(error)
            case .available(let release):
                LabeledContent("New version", value: release.version.description)
                LabeledContent("Released", value: release.published.formatted(date: .abbreviated, time: .omitted))
                releaseNotes(release.notes)
                actionRows(for: release)
            }
        } header: {
            Text("App updates")
        } footer: {
            Text("Bluehat contacts GitHub only when you click Check for Updates or Update and Relaunch. It installs an update only if the download is signed by an update key built into this app. The release notes come from GitHub and aren't covered by that signature.")
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
        }
    }

    private var checkRow: some View {
        HStack(spacing: Metrics.spaceMedium) {
            Button("Check for Updates") {
                Task { await update.check() }
            }
            .disabled(!update.canCheck)
            if update.activity == .checking {
                ProgressView()
                    .controlSize(.small)
                    .accessibilityLabel("Checking")
            } else if update.currentVersion == nil {
                Text("Development builds can't check for updates.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            } else if case .upToDate = update.status {
                Label("Up to date", systemImage: "checkmark.circle.fill")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.safe)
            }
        }
    }

    private func releaseNotes(_ notes: String) -> some View {
        ScrollView {
            Text(notes.isEmpty ? AttributedString("This release has no notes.") : Self.formatted(notes))
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .overlayScrollers()
        }
        .frame(height: Metrics.releaseNotesHeight)
        .accessibilityLabel("Release notes")
    }

    @ViewBuilder private func actionRows(for release: AppRelease) -> some View {
        switch update.activity {
        case .downloading(let received, let total):
            downloadRows(received: received, total: total)
        case .installing:
            workingRow("Verifying and installing…")
        case .relaunching:
            workingRow("Relaunching…")
        case .checking, nil:
            if let refusal = update.installRefusal {
                problemRows(refusal)
            } else {
                if let problem = update.updateProblem {
                    problemRows(problem)
                }
                HStack(spacing: Metrics.spaceMedium) {
                    Link("View on GitHub", destination: release.pageURL)
                    Spacer()
                    Button("Update and Relaunch") { store.startAppUpdate() }
                        .buttonStyle(.borderedProminent)
                        .disabled(store.isBusy)
                }
                if store.isBusy {
                    Text("You can update when the scan finishes.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
        }
    }

    private func downloadRows(received: Int, total: Int) -> some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            ProgressView(value: total > 0 ? Double(received) / Double(total) : 0)
                .accessibilityLabel("Download progress")
            HStack(spacing: Metrics.spaceMedium) {
                Text(total > 0 ? "Downloading \(Int64(received).formatted(.byteCount(style: .file))) of \(Int64(total).formatted(.byteCount(style: .file)))" : "Downloading…")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                Spacer()
                Button("Cancel") { update.cancelDownload() }
            }
        }
    }

    private func workingRow(_ title: String) -> some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            ProgressView()
                .progressViewStyle(.linear)
                .accessibilityLabel(title)
            Text(title)
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
                .accessibilityHidden(true)
        }
    }

    @ViewBuilder private func problemRows(_ error: AppUpdateError) -> some View {
        Label(error.localizedDescription, systemImage: "exclamationmark.triangle.fill")
            .font(Typography.caption)
            .foregroundStyle(Palette.failure)
            .fixedSize(horizontal: false, vertical: true)
        Link("Open Releases Page", destination: AppUpdater.releasesURL)
    }

    private static func formatted(_ notes: String) -> AttributedString {
        let options = AttributedString.MarkdownParsingOptions(interpretedSyntax: .inlineOnlyPreservingWhitespace)
        var text = (try? AttributedString(markdown: notes, options: options)) ?? AttributedString(notes)
        for run in text.runs where run.link != nil {
            text[run.range].link = nil
        }
        return text
    }
}
