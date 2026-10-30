import AppKit
import BluehatCore
import SwiftUI

struct WelcomeView: View {
    static let windowID = "welcome"

    let store: ScanStore
    @State private var opensAtLogin = false
    @State private var scansAutomatically = true
    @Environment(\.dismissWindow) private var dismissWindow

    private var settings: SettingsStore {
        store.settings
    }

    var body: some View {
        VStack(spacing: Metrics.spaceSection) {
            ShieldEmblem(tint: Palette.brand, face: .symbol("checkmark"), size: Metrics.welcomeEmblem, isFloating: false)
                .padding(.top, Metrics.spaceSection)
            VStack(spacing: Metrics.spaceSmall) {
                Text("Welcome to Bluehat")
                    .font(Typography.welcomeTitle)
                Text("Bluehat checks your Mac for remote code execution, malware, worms, backdoors and weak settings. It lives in the menu bar.")
                    .font(Typography.body)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: Metrics.spaceLarge) {
                feature("checkmark.seal.fill", tint: Palette.safe, title: "Signed rules only", text: "Rules come only from \(RuleFeed.repositoryURL.path().dropFirst()) and must carry your signature. They are data, so they can't make Bluehat run anything.")
                feature("hand.raised.fill", tint: Palette.brand, title: "Reports, never deletes", text: "Bluehat reads and reports. You decide what to fix, with steps for each finding.")
                feature("folder.fill", tint: Palette.notice, title: "Folder access", text: "macOS will ask to let Bluehat read Downloads and Desktop to fingerprint files. If you say no, only that check is skipped.")
            }
            .padding(Metrics.cardPadding)
            .card()
            VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                Toggle("Scan every 6 hours and notify me about new issues", isOn: $scansAutomatically)
                Toggle("Open Bluehat when I log in", isOn: $opensAtLogin)
                if !settings.isInstalled {
                    Text("Install Bluehat in Applications first for a reliable login item (devbox run install).")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.tertiaryText)
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            Button(action: finish) {
                Text("Get Started")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .keyboardShortcut(.defaultAction)
        }
        .padding(Metrics.welcomePadding)
        .frame(width: Metrics.welcomeWidth)
        .onAppear {
            opensAtLogin = settings.isInstalled
            NSApplication.shared.activate()
        }
    }

    private func feature(_ symbol: String, tint: Color, title: String, text: String) -> some View {
        HStack(alignment: .top, spacing: Metrics.spaceMedium) {
            Image(systemName: symbol)
                .font(Typography.featureSymbol)
                .foregroundStyle(tint)
                .frame(width: Metrics.featureSymbolWidth)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text(title)
                    .font(Typography.rowTitle)
                Text(text)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private func finish() {
        if scansAutomatically {
            settings.schedule = .everySixHours
            settings.notifiesNewIssues = true
        }
        if opensAtLogin {
            settings.setLaunchesAtLogin(true)
        }
        settings.hasSeenWelcome = true
        dismissWindow(id: Self.windowID)
        Task { await store.scan() }
    }
}
