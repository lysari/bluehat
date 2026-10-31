import AppKit
import BluehatCore
import SwiftUI

struct ScanPanel: View {
    let store: ScanStore
    @State private var selectedFindingID: Finding.ID?
    @Environment(\.openURL) private var openURL
    @Environment(\.openSettings) private var openSettings
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var selectedFinding: Finding? {
        store.visibleFindings.first { $0.id == selectedFindingID }
    }

    private var hasFindings: Bool {
        !store.visibleFindings.isEmpty
    }

    var body: some View {
        HStack(alignment: .top, spacing: 0) {
            overview
            ZStack(alignment: .topLeading) {
                if hasFindings {
                    findingsColumn
                        .padding(.leading, Metrics.spaceSection)
                        .transition(.opacity)
                }
            }
            .animation(Motion.standard, value: hasFindings)
            .frame(maxHeight: .infinity, alignment: .topLeading)
            .modifier(ColumnReveal(width: hasFindings ? Metrics.spaceSection + Metrics.findingsColumnWidth : 0))
            .animation(reduceMotion ? nil : Motion.standard, value: hasFindings)
        }
        .padding(Metrics.panelPadding)
        .animation(Motion.standard, value: store.phase)
    }

    private var findingsColumn: some View {
        ZStack(alignment: .top) {
            if let selectedFinding {
                ScrollView {
                    FindingDetailView(finding: selectedFinding, store: store) {
                        selectedFindingID = nil
                    } onIgnore: {
                        store.settings.ignore(selectedFinding)
                        selectedFindingID = nil
                    }
                }
                .scrollClipDisabled()
                .id(selectedFinding.id)
                .transition(.move(edge: .trailing).combined(with: .opacity))
            } else {
                findingsSection
                    .transition(.move(edge: .leading).combined(with: .opacity))
            }
        }
        .frame(width: Metrics.findingsColumnWidth)
        .frame(minHeight: 0, idealHeight: 0, maxHeight: .infinity, alignment: .top)
        .clipShape(Rectangle().inset(by: -Metrics.cardStrokeWidth))
        .animation(Motion.standard, value: selectedFinding?.id)
    }

    private var overview: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSection) {
            header
            statusCard
            if let notice = store.notice {
                Label(notice, systemImage: "exclamationmark.triangle.fill")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if store.rulesExpireSoon, let expires = store.rulebook?.expires {
                Label("Rules expire \(expires.formatted(.relative(presentation: .named))), on \(expires.formatted(date: .abbreviated, time: .omitted)). Sign and push new rules, or check that nothing is blocking updates.", systemImage: "clock.badge.exclamationmark")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
                    .fixedSize(horizontal: false, vertical: true)
            }
            checksSection
            footer
        }
        .frame(width: Metrics.overviewColumnWidth)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var header: some View {
        HStack(spacing: Metrics.spaceMedium) {
            ShieldEmblem(tint: Palette.brand, face: nil, size: Metrics.appIcon, isFloating: false)
            VStack(alignment: .leading, spacing: Metrics.spaceTight) {
                Text("Bluehat")
                    .font(Typography.appTitle)
                Text("Threat scanner for macOS")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            Spacer()
            Menu {
                Button("Settings…") {
                    openSettings()
                    NSApplication.shared.activate()
                }
                .keyboardShortcut(",")
                Button("Open Rules Repository") { openURL(RuleFeed.repositoryURL) }
                Divider()
                Button("Quit Bluehat") { NSApplication.shared.terminate(nil) }
                    .keyboardShortcut("q")
            } label: {
                Image(systemName: "ellipsis.circle")
                    .font(Typography.headerAction)
                    .foregroundStyle(Palette.secondaryText)
            }
            .menuStyle(.button)
            .buttonStyle(.borderless)
            .menuIndicator(.hidden)
            .fixedSize()
            .accessibilityLabel("More")
        }
    }

    private var statusCard: some View {
        VStack(spacing: Metrics.spaceLarge) {
            ScanRing(store: store, tint: statusTint, face: emblemFace)
                .padding(.top, Metrics.heroTopPadding)
            VStack(spacing: Metrics.spaceTight) {
                Text(statusTitle)
                    .font(Typography.statusTitle)
                Text(statusSubtitle)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .accessibilityElement(children: .combine)
            Button {
                Task { await store.scan() }
            } label: {
                Label(buttonTitle, systemImage: "magnifyingglass")
                    .frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .controlSize(.large)
            .disabled(store.isBusy)
            .keyboardShortcut(.defaultAction)
        }
        .padding(Metrics.cardPadding)
        .frame(maxWidth: .infinity)
        .card(wash: statusTint)
    }

    private var emblemFace: ShieldEmblem.Face {
        if store.failure != nil { return .symbol("xmark") }
        switch store.phase {
        case .idle: return .symbol("magnifyingglass")
        case .loadingRules: return .symbol("key.fill")
        case .scanning: return .text("\(Int(store.progress * 100))%")
        case .finished: return store.issues.isEmpty ? .symbol("checkmark") : .text("\(store.issues.count)")
        }
    }

    private var statusTint: Color {
        if store.failure != nil { return Palette.failure }
        switch store.phase {
        case .idle, .loadingRules, .scanning: return Palette.idle
        case .finished: return store.issues.map(\.rule.severity).max().map(Palette.severity) ?? Palette.safe
        }
    }

    private var statusTitle: String {
        if store.failure != nil { return "Couldn't load rules" }
        switch store.phase {
        case .idle: return "Ready to scan"
        case .loadingRules: return "Verifying signed rules…"
        case .scanning: return "Scanning your Mac…"
        case .finished:
            if store.issues.isEmpty { return "Your Mac looks safe" }
            return store.issues.count == 1 ? "1 issue needs attention" : "\(store.issues.count) issues need attention"
        }
    }

    private var statusSubtitle: String {
        if let failure = store.failure { return failure }
        let ruleCount = store.rulebook?.rules.count ?? 0
        switch store.phase {
        case .idle: return "Checks for remote code execution, malware, worms, backdoors and weak settings."
        case .loadingRules: return "Downloading rules and checking their signature."
        case .scanning: return "Checking \(store.currentArea?.title.lowercased() ?? "results")…"
        case .finished:
            let time = store.lastScanAt?.formatted(date: .omitted, time: .shortened) ?? ""
            let duration = store.scanDuration?.formatted(.units(allowed: [.seconds, .milliseconds], width: .narrow, maximumUnitCount: 1)) ?? ""
            let notes = store.notes.isEmpty ? "" : " · \(counted(store.notes.count, "note"))"
            let ignored = store.ignoredCount == 0 ? "" : " · \(store.ignoredCount) ignored"
            let newCount = store.history.latestChanges?.new.count ?? 0
            let resolvedCount = store.history.latestChanges?.resolved.count ?? 0
            let newText = newCount == 0 ? "" : " · \(newCount) new"
            let resolvedText = resolvedCount == 0 ? "" : " · \(resolvedCount) resolved"
            return "\(counted(ruleCount, "check")) in \(duration) · \(time)\(notes)\(ignored)\(newText)\(resolvedText)"
        }
    }

    private var buttonTitle: String {
        switch store.phase {
        case .idle: "Scan Now"
        case .loadingRules, .scanning: "Scanning…"
        case .finished: "Scan Again"
        }
    }

    private var findingsSection: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            sectionTitle("Findings")
            ScrollView { findingRows }
                .padding(.horizontal, Metrics.cardPadding)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .card()
        }
    }

    private var findingRows: some View {
        VStack(spacing: 0) {
            ForEach(store.visibleFindings) { finding in
                FindingRow(finding: finding) { selectedFindingID = finding.id }
                if finding.id != store.visibleFindings.last?.id {
                    Divider()
                }
            }
        }
    }

    private var checksSection: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            sectionTitle("What Bluehat checks")
            LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)], spacing: Metrics.spaceMedium) {
                ForEach(store.areas, id: \.self) { area in
                    CheckRow(kind: area, findings: store.visibleFindings.filter { $0.rule.check == area }, isChecked: store.finishedAreas.contains(area))
                }
            }
            .padding(Metrics.cardPadding)
            .card()
        }
    }

    private var footer: some View {
        HStack(spacing: Metrics.spaceSmall) {
            Image(systemName: store.rulebook == nil ? "seal" : "checkmark.seal.fill")
                .foregroundStyle(store.rulebook == nil ? Palette.tertiaryText : Palette.safe)
                .accessibilityHidden(true)
            Text(store.rulebook.map { "Signed rules v" + String($0.version) } ?? "Rules are verified before every scan")
                .foregroundStyle(Palette.secondaryText)
            Spacer()
            Text(RuleFeed.repositoryURL.path().trimmingCharacters(in: CharacterSet(charactersIn: "/")))
                .foregroundStyle(Palette.tertiaryText)
        }
        .font(Typography.caption)
    }

    private func sectionTitle(_ title: String) -> some View {
        Text(title.uppercased())
            .font(Typography.sectionTitle)
            .foregroundStyle(Palette.secondaryText)
            .padding(.leading, Metrics.spaceTight)
            .accessibilityAddTraits(.isHeader)
    }
}

@Animatable
private struct ColumnReveal: ViewModifier {
    var width: CGFloat

    func body(content: Content) -> some View {
        content
            .frame(width: max(width, 0), alignment: .leading)
            .clipShape(Rectangle().inset(by: -Metrics.cardStrokeWidth))
    }
}
