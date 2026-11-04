import BluehatCore
import SwiftUI

struct ScheduleSettingsTab: View {
    let store: ScanStore

    private var settings: SettingsStore {
        store.settings
    }

    var body: some View {
        @Bindable var settings = settings
        Form {
            Section {
                Picker("Scan automatically", selection: $settings.schedule) {
                    ForEach(ScanSchedule.allCases) { schedule in
                        Text(schedule.title).tag(schedule)
                    }
                }
                if settings.schedule == .custom, let customScanAt = settings.customScanAt {
                    customScanPicker(customScanAt)
                }
                Toggle("Notify me about new issues", isOn: $settings.notifiesNewIssues)
                    .disabled(settings.schedule == .off)
                if let problem = settings.notificationProblem {
                    Text(problem)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.notice)
                }
            } footer: {
                Text(footerText)
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            .overlayScrollers(flashesOnAppear: true)
            Section {
                LabeledContent("Last scan", value: store.lastScanAt?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                TimelineView(.everyMinute) { _ in
                    LabeledContent("Next scan", value: nextScanText)
                }
                if let lastCustomScanAt = settings.lastCustomScanAt {
                    LabeledContent("Last custom scan", value: lastCustomScanAt.formatted(date: .abbreviated, time: .shortened))
                }
            }
        }
        .formStyle(.grouped)
        .animation(Motion.standard, value: settings.schedule)
    }

    private var footerText: String {
        let scheduled = "Scheduled scans run in the background while Bluehat is open. You get a notification only for issues that weren't there in the last scan."
        guard settings.schedule == .custom else { return scheduled }
        return scheduled + " A custom scan runs once, then the schedule turns Off. If the Mac is asleep or Bluehat is closed at that time, it runs as soon as it can. If another scan is running, it waits for that scan to finish."
    }

    private var nextScanText: String {
        guard let next = store.nextScheduledScan else { return "Not scheduled" }
        guard next <= .now else { return next.formatted(date: .abbreviated, time: .shortened) }
        guard settings.schedule == .custom, store.isBusy else { return "Within a minute" }
        return store.runningCustomScanAt == next ? "Running now" : "After the current scan"
    }

    private func customScanPicker(_ customScanAt: Date) -> some View {
        TimelineView(.everyMinute) { context in
            DatePicker(
                "Scan on",
                selection: Binding { customScanAt } set: { settings.chooseCustomScan(at: $0) },
                in: min(customScanAt, ScanSchedule.earliestCustomScan(after: context.date))...,
                displayedComponents: [.date, .hourAndMinute]
            )
            .disabled(customScanAt <= context.date)
        }
    }
}
