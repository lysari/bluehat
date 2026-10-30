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
                Toggle("Notify me about new issues", isOn: $settings.notifiesNewIssues)
                    .disabled(settings.schedule == .off)
                if let problem = settings.notificationProblem {
                    Text(problem)
                        .font(Typography.caption)
                        .foregroundStyle(Palette.notice)
                }
            } footer: {
                Text("Scheduled scans run in the background while Bluehat is open. You get a notification only for issues that weren't there in the last scan.")
                    .font(Typography.caption)
                    .foregroundStyle(Palette.secondaryText)
            }
            Section {
                LabeledContent("Last scan", value: store.lastScanAt?.formatted(date: .abbreviated, time: .shortened) ?? "Never")
                LabeledContent("Next scan", value: nextScanText)
            }
        }
        .formStyle(.grouped)
    }

    private var nextScanText: String {
        guard let next = store.nextScheduledScan else { return "Not scheduled" }
        return next <= .now ? "Within a minute" : next.formatted(date: .abbreviated, time: .shortened)
    }
}
