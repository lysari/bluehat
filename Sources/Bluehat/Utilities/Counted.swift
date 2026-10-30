/// Formats a count with its noun, adding "s" when the count is not one. Pass the count and the singular noun, e.g. `counted(3, "issue")`.
func counted(_ count: Int, _ noun: String) -> String {
    "\(count) \(noun)\(count == 1 ? "" : "s")"
}
