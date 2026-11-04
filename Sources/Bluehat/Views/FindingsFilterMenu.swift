import BluehatCore
import SwiftUI

struct FindingsFilterMenu: View {
    let store: ScanStore

    private var isNotScannedTab: Bool {
        store.findingsTab == .notScanned
    }

    private var activeCount: Int {
        isNotScannedTab ? store.filter.reasons.count : store.filter.severities.count + store.filter.checks.count
    }

    var body: some View {
        Menu {
            if isNotScannedTab {
                notScannedSections
            } else {
                findingSections
            }
            if activeCount > 0 {
                Divider()
                Button("Reset Filters") { store.filter.reset() }
            }
        } label: {
            Label(activeCount == 0 ? "Filter" : "Filter (\(activeCount))", systemImage: activeCount == 0 ? "line.3.horizontal.decrease.circle" : "line.3.horizontal.decrease.circle.fill")
        }
        .menuStyle(.button)
        .buttonStyle(.bordered)
        .tint(activeCount == 0 ? nil : Palette.brand)
        .fixedSize()
        .help("Filter this list")
        .accessibilityLabel(activeCount == 0 ? "Filter" : "Filter, \(activeCount) active")
    }

    @ViewBuilder
    private var findingSections: some View {
        let findings = store.visibleFindings
        let severities = Dictionary(grouping: findings, by: \.rule.severity)
        let checks = Dictionary(grouping: findings, by: \.rule.check)
        Section("Severity") {
            ForEach(Array(store.filter.severities.union(severities.keys)).sorted(by: >), id: \.self) { severity in
                Toggle("\(severity.rawValue.capitalized) (\(severities[severity]?.count ?? 0))", isOn: membership(of: severity, in: \.severities))
            }
        }
        Section("Check Type") {
            ForEach(CheckKind.allCases.filter { checks[$0] != nil || store.filter.checks.contains($0) }, id: \.self) { check in
                Toggle("\(check.title) (\(checks[check]?.count ?? 0))", isOn: membership(of: check, in: \.checks))
            }
        }
    }

    private var notScannedSections: some View {
        Section("Reason") {
            ForEach(store.notScanned.reasons) { reason in
                Toggle("\(reason.title) (\((store.notScanned.totalsByReason[reason] ?? 0).formatted()))", isOn: membership(of: reason, in: \.reasons))
            }
        }
    }

    private func membership<Value: Hashable>(of value: Value, in choices: WritableKeyPath<FindingsFilter, Set<Value>>) -> Binding<Bool> {
        Binding {
            store.filter[keyPath: choices].contains(value)
        } set: { isOn in
            if isOn {
                store.filter[keyPath: choices].insert(value)
            } else {
                store.filter[keyPath: choices].remove(value)
            }
        }
    }
}
