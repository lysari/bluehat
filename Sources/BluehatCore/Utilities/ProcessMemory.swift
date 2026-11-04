import Darwin

enum ProcessMemory {
    /// Returns this process's memory use in bytes as macOS accounts it (`phys_footprint`, what Activity Monitor shows), or nil when the kernel refuses the call.
    /// Use it to compare against a memory limit, at an interval rather than on every item.
    @Sendable
    static func footprintBytes() -> Int? {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<natural_t>.size)
        let result = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count)
            }
        }
        return result == KERN_SUCCESS ? Int(info.phys_footprint) : nil
    }
}
