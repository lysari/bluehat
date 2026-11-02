import BluehatCore
import SwiftUI

struct RulesSettingsTab: View {
    let rules: FeedReview<Rulebook>
    let malwareFeed: FeedReview<MalwareFeed>

    private var isBusy: Bool {
        rules.isBusy || malwareFeed.isBusy
    }

    private var checkResult: String? {
        if rules.isUpdateAvailable && malwareFeed.isUpdateAvailable { return "Updates available for rules and fingerprints" }
        if rules.isUpdateAvailable { return "Update available for rules" }
        if malwareFeed.isUpdateAvailable { return "Update available for fingerprints" }
        return rules.isUpToDate && malwareFeed.isUpToDate ? "Everything is up to date" : nil
    }

    var body: some View {
        Form {
            checkSection
            rulesSection
            malwareFeedSection
        }
        .formStyle(.grouped)
        .animation(Motion.standard, value: isBusy)
        .animation(Motion.standard, value: rules.isUpdateAvailable)
        .animation(Motion.standard, value: malwareFeed.isUpdateAvailable)
        .task {
            async let rulesLoad: Void = rules.loadLocal()
            async let feedLoad: Void = malwareFeed.loadLocal()
            _ = await (rulesLoad, feedLoad)
        }
    }

    private var checkSection: some View {
        Section {
            HStack(spacing: Metrics.spaceMedium) {
                Button("Check for Updates") {
                    Task {
                        async let rulesCheck: Void = rules.check()
                        async let feedCheck: Void = malwareFeed.check()
                        _ = await (rulesCheck, feedCheck)
                    }
                }
                .disabled(isBusy)
                if isBusy {
                    ProgressView()
                        .controlSize(.small)
                        .accessibilityLabel("Working")
                } else if let checkResult {
                    Text(checkResult)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
            }
        } footer: {
            Text("Bluehat contacts the rules repository only when you click Check for Updates. Scans use the local files, and nothing changes until you accept an update.")
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
        }
        .overlayScrollers()
    }

    private var rulesSection: some View {
        Section("Rules") {
            FeedUpdateRows(review: rules, feedName: "rules") { changes in
                if changes.isEmpty {
                    Text("No rules changed. This update only renews the signature and expiry.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                }
                RuleChangeGroup(title: "Added", rules: changes.added)
                RuleChangeGroup(title: "Changed", rules: changes.changed)
                RuleChangeGroup(title: "Removed", rules: changes.removed)
                if case .available(let update) = rules.status, update.payload.unsupportedRuleCount > 0 {
                    Text("\(counted(update.payload.unsupportedRuleCount, "rule")) in this update need a newer version of Bluehat and would be skipped.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.notice)
                }
            }
            LabeledContent("Rules", value: rules.local.map { $0.payload.rules.count.formatted() } ?? "Unknown")
            LabeledContent(RuleFeed.trustedKeys.count == 1 ? "Rules key" : "Rules keys") {
                VStack(alignment: .trailing, spacing: Metrics.spaceTight) {
                    ForEach(RuleFeed.trustedKeys.map(RuleFeed.fingerprint(of:)), id: \.self) { fingerprint in
                        Text(fingerprint)
                            .font(Typography.detail)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private var malwareFeedSection: some View {
        Section {
            FeedUpdateRows(review: malwareFeed, feedName: "malware fingerprints") { changes in
                feedChangeRow("Fingerprint changes", changes.hashes)
                feedChangeRow("npm package changes", changes.packages)
                feedChangeRow("C2 address changes", changes.hosts)
            }
            LabeledContent("Fingerprints", value: malwareFeed.local.map { $0.payload.hashes.count.formatted() } ?? "Unknown")
            LabeledContent("npm packages", value: malwareFeed.local.map { $0.payload.packages.count.formatted() } ?? "Unknown")
            LabeledContent("C2 addresses", value: malwareFeed.local.map { $0.payload.hosts.count.formatted() } ?? "Unknown")
            LabeledContent("Feed key") {
                Text(RuleFeed.fingerprint(of: RuleFeed.feedKey))
                    .font(Typography.detail)
                    .textSelection(.enabled)
            }
        } header: {
            Text("Malware fingerprints")
        } footer: {
            Text("Built daily in the repository from MalwareBazaar, OSV and ThreatFox, and valid for 7 days. Once the local copy expires, scans run with the rules alone until you accept a new one. The feed key can sign only the fingerprints, npm packages and C2 addresses, never the rules; the rules keys can sign both.")
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
        }
    }

    private func feedChangeRow<Entry>(_ title: String, _ changes: EntryChanges<Entry>) -> some View {
        LabeledContent(title, value: changes.isEmpty ? "No changes" : "\(changes.added.count.formatted()) added, \(changes.changed.count.formatted()) changed, \(changes.removed.count.formatted()) removed")
    }
}

private struct FeedUpdateRows<Payload: SignedPayload, Changes: View>: View {
    let review: FeedReview<Payload>
    let feedName: String
    @ViewBuilder let changes: (Payload.Changes) -> Changes

    var body: some View {
        LabeledContent {
            Text(updateDate(of: review.local?.payload))
        } label: {
            Text("Local update")
            if let version = review.local?.payload.version {
                Text("v\(String(version))")
            }
        }
        if let remote = review.remote {
            LabeledContent {
                Text(updateDate(of: remote))
            } label: {
                Text("Repository update")
                Text("v\(String(remote.version))")
            }
        }
        expiryRow
        if let problem = review.localProblem {
            problemLabel("The local \(feedName) couldn't be loaded. \(problem)")
        }
        if let storedError = review.local?.storedError {
            problemLabel("The saved \(feedName) failed verification, so the copy built into Bluehat is used. \(storedError.localizedDescription)")
        }
        statusRows
        if let actionProblem = review.actionProblem {
            problemLabel(actionProblem)
        }
    }

    @ViewBuilder private var expiryRow: some View {
        if let expires = review.local?.payload.expires {
            LabeledContent("Expires") {
                Text(expires <= .now ? "Expired \(expires.formatted(date: .abbreviated, time: .shortened))" : expires.formatted(date: .abbreviated, time: .shortened))
                    .foregroundStyle(expires <= .now ? Palette.failure : Palette.secondaryText)
            }
        }
    }

    @ViewBuilder private var statusRows: some View {
        switch review.status {
        case .notChecked:
            EmptyView()
        case .upToDate:
            Label("Up to date", systemImage: "checkmark.circle.fill")
                .foregroundStyle(Palette.safe)
        case .failed(let message):
            problemLabel(message)
        case .available(let update):
            Label("Update available", systemImage: "arrow.down.circle.fill")
                .foregroundStyle(Palette.brand)
            changes(update.changes)
            HStack(spacing: Metrics.spaceMedium) {
                Button("Open Full File") { Task { await review.openFullFile() } }
                Spacer()
                Button("Decline") { review.decline() }
                Button("Accept Update") { Task { await review.accept() } }
                    .buttonStyle(.borderedProminent)
            }
            .disabled(review.isBusy)
        }
    }

    private func updateDate(of payload: Payload?) -> String {
        payload?.issued?.formatted(date: .abbreviated, time: .shortened) ?? "Unknown"
    }

    private func problemLabel(_ message: String) -> some View {
        Label(message, systemImage: "exclamationmark.triangle.fill")
            .font(Typography.caption)
            .foregroundStyle(Palette.failure)
            .fixedSize(horizontal: false, vertical: true)
    }
}

private struct RuleChangeGroup: View {
    let title: String
    let rules: [Rule]
    @State private var isExpanded = true

    var body: some View {
        if !rules.isEmpty {
            DisclosureGroup("\(title) (\(rules.count.formatted()))", isExpanded: $isExpanded) {
                VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
                    ForEach(rules) { rule in
                        VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                            Text(rule.title)
                                .font(Typography.rowTitle)
                            Text(rule.id)
                                .font(Typography.detail)
                                .foregroundStyle(Palette.secondaryText)
                                .textSelection(.enabled)
                        }
                        .accessibilityElement(children: .combine)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, Metrics.spaceSmall)
            }
        }
    }
}
