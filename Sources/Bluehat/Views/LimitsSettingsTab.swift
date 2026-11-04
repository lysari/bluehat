import BluehatCore
import SwiftUI

struct LimitsSettingsTab: View {
    let settings: SettingsStore
    @State private var isConfirmingReset = false
    @State private var resetCount = 0

    var body: some View {
        ScrollViewReader { scroller in
            Form {
                Section {
                    if let problem = settings.scanLimitsProblem {
                        Text(problem)
                            .font(Typography.caption)
                            .foregroundStyle(Palette.notice)
                    }
                    Text("Changes apply to the next scan. A scan that is running keeps the limits it started with.")
                        .font(Typography.caption)
                        .foregroundStyle(Palette.secondaryText)
                    Button("Reset All to Defaults…") { isConfirmingReset = true }
                        .disabled(settings.scanLimits.isDefault && settings.scanLimitsProblem == nil)
                        .confirmationDialog("Reset all limits to their defaults?", isPresented: $isConfirmingReset, titleVisibility: .visible) {
                            Button("Reset All", role: .destructive, action: resetAll)
                        } message: {
                            Text("Every limit goes back to the value Bluehat ships with. The next scan uses them.")
                        }
                }
                .overlayScrollers(flashesOnAppear: true)
                ForEach(ScanLimit.Area.allCases) { area in
                    Section(area.title) {
                        ForEach(ScanLimit.all.filter { $0.area == area }) { limit in
                            ScanLimitRow(limit: limit, settings: settings, scroller: scroller)
                                .id("\(limit.key)-\(resetCount)")
                        }
                    }
                }
            }
            .formStyle(.grouped)
        }
    }

    private func resetAll() {
        settings.resetAllScanLimits()
        resetCount += 1
    }
}

private struct ScanLimitRow: View {
    let limit: ScanLimit
    let settings: SettingsStore
    let scroller: ScrollViewProxy
    @State private var text = ""
    @State private var isRefused = false
    @FocusState private var isEditing: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    private var value: Int {
        settings.scanLimits[limit]
    }

    private var defaultText: String {
        limit.text(for: limit.defaultValue)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Metrics.spaceSmall) {
            HStack(spacing: Metrics.spaceMedium) {
                Text(limit.title)
                    .font(Typography.rowTitle)
                    .accessibilityHidden(true)
                Spacer()
                if value != limit.defaultValue {
                    Button("Reset", systemImage: "arrow.counterclockwise") { settings.resetScanLimit(limit) }
                        .labelStyle(.iconOnly)
                        .buttonStyle(.borderless)
                        .foregroundStyle(Palette.secondaryText)
                        .help("Reset to \(defaultText)")
                        .accessibilityLabel("Reset \(limit.title) in \(limit.area.title) to \(defaultText)")
                }
                TextField(limit.title, text: $text, prompt: Text(limit.editableText(for: limit.defaultValue)))
                    .font(Typography.body.monospacedDigit())
                    .multilineTextAlignment(.trailing)
                    .textFieldStyle(.roundedBorder)
                    .labelsHidden()
                    .autocorrectionDisabled()
                    .frame(width: Metrics.limitFieldWidth)
                    .focused($isEditing)
                    .onSubmit(commit)
                    .onExitCommand(perform: showSavedValue)
                    .accessibilityLabel("\(limit.title) in \(limit.area.title), \(limit.unitLabel)")
                    .accessibilityHint(limit.refusalMessage)
                Text(limit.unitLabel)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
                    .frame(width: Metrics.limitUnitWidth, alignment: .leading)
                    .accessibilityHidden(true)
            }
            Text(limit.help)
                .font(Typography.caption)
                .foregroundStyle(Palette.secondaryText)
                .fixedSize(horizontal: false, vertical: true)
            if isRefused {
                Text(limit.refusalMessage)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.notice)
            } else if value < limit.defaultValue {
                Text("Lowered from \(defaultText), so scans may miss things.")
                    .font(Typography.captionEmphasis)
                    .foregroundStyle(Palette.notice)
            } else if value > limit.defaultValue {
                Text("Raised from \(defaultText).")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
        }
        .id(limit.key)
        .animation(Motion.standard, value: isRefused)
        .animation(Motion.standard, value: value)
        .onAppear(perform: showSavedValue)
        .onChange(of: value, showSavedValue)
        .onChange(of: text) { isRefused = false }
        .onChange(of: isEditing) {
            if !isEditing { commit() }
        }
    }

    private func showSavedValue() {
        text = limit.editableText(for: value)
        isRefused = false
    }

    private func commit() {
        guard text != limit.editableText(for: value) else { return }
        guard let entered = limit.value(entered: text), settings.setScanLimit(limit, to: entered) else {
            isRefused = true
            AccessibilityNotification.Announcement(limit.refusalMessage).post()
            revealWhileEditing()
            return
        }
        showSavedValue()
        revealWhileEditing()
    }

    private func revealWhileEditing() {
        guard isEditing else { return }
        withAnimation(reduceMotion ? nil : Motion.standard) { scroller.scrollTo(limit.key) }
    }
}
