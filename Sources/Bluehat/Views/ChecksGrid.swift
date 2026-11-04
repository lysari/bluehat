import BluehatCore
import SwiftUI

struct ChecksGrid: View {
    let progress: CheckProgress
    let findings: [Finding]
    let visibleFindings: [Finding]
    let walkedItemCount: Int
    let walkFindingIDs: Set<Finding.ID>

    var body: some View {
        let visibleByArea = Dictionary(grouping: visibleFindings, by: \.rule.check)
        let allByArea = Dictionary(grouping: findings, by: \.rule.check)
        VStack(spacing: Metrics.spaceMedium) {
            LazyVGrid(columns: [GridItem(.flexible(), spacing: Metrics.spaceSmall, alignment: .leading), GridItem(.flexible(), alignment: .leading)], spacing: Metrics.spaceMedium) {
                ForEach(CheckKind.allCases, id: \.self) { area in
                    let shown = visibleByArea[area] ?? []
                    CheckRow(title: area.title, symbol: area.symbol, details: area.details, status: progress.status(of: area), findings: shown, ignoredCount: (allByArea[area]?.count ?? 0) - shown.count)
                }
            }
            if progress.showsDiskWalk {
                Divider()
                diskWalkRow
            }
        }
        .padding(Metrics.cardPadding)
        .card()
    }

    private var diskWalkRow: some View {
        let shown = visibleFindings.filter { walkFindingIDs.contains($0.id) }
        return CheckRow(title: CheckDetails.diskWalkTitle, symbol: CheckDetails.diskWalkSymbol, details: .diskWalk, status: progress.diskWalkStatus, findings: shown, ignoredCount: walkFindingIDs.count - shown.count, walkedItemCount: walkedItemCount)
    }
}
