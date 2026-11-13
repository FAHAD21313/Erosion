//
//  AppLimitInspectorView.swift
//  Erosion
//
//  Read-only iOS 27 installation diagnostics.
//  This feature does not modify installed app bundles or provisioning data.
//

import SwiftUI
import Foundation
import Darwin

struct AppLimitInspectorView: View {
    @State private var isRunning = false
    @State private var report = ""

    var body: some View {
        List {
            Section {
                Text("Research tool for the free developer account's three-app limit on iOS 27.")
                Text("Checks sandbox access, bundle directory visibility, ownership and a provisioning-related extended attribute. It does not bypass the limit or modify installed apps.")
                Text("The worse_query probe temporarily recreates the cache directory in this app’s own App Group.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)
            } header: {
                HeaderLabel("About", symbol: "info.circle")
            }

            Section {
                Button {
                    runScan()
                } label: {
                    Label(isRunning ? "Scanning…" : "Run Read-Only Scan", systemImage: "magnifyingglass")
                }
                .disabled(isRunning)

                if isRunning {
                    ProgressView("Testing paths and locating sample bundles…")
                }
            } header: {
                HeaderLabel("Diagnostics", symbol: "stethoscope")
            }

            if !report.isEmpty {
                Section {
                    Text(report)
                        .font(.system(size: 11, design: .monospaced))
                        .textSelection(.enabled)

                    ShareLink(item: report) {
                        Label("Share Report", systemImage: "square.and.arrow.up")
                    }
                } header: {
                    HeaderLabel("Results", symbol: "doc.text")
                }
            }
        }
        .navigationTitle("App Limit Inspector")
    }

    private func runScan() {
        guard !isRunning else { return }
        isRunning = true

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                AppLimitInspector.generateReport()
            }.value
            report = result
            isRunning = false
        }
    }
}

private enum AppLimitInspector {
    private static let appBundleRoot = "/var/containers/Bundle/Application"
    private static let appDataRoot = "/var/mobile/Containers/Data/Application"
    private static let daemonRoot = "/var/mobile/Containers/Data/InternalDaemon"
    private static let attribute = "com.apple.installd.validatedByFreeProfile"

    static func generateReport() -> String {
        var lines: [String] = [
            "Erosion / App Limit Inspector v2 (read-only)",
            "Date: \(ISO8601DateFormatter().string(from: Date()))",
            "OS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "Build: \(buildNumber())",
            "Test: iOS 27 sandbox extensions, standard and alternate flags",
            ""
        ]

        let appGroup = wq.getAppGroup()
        let groupAvailable = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup
        ) != nil
        lines.append("App Group container: \(groupAvailable ? "available" : "unavailable")")
        lines.append("Report excludes app identifiers, container UUIDs and provisioning contents.")
        lines.append("Sandbox grants do not change POSIX ownership.")
        lines.append("")

        guard groupAvailable else {
            lines.append("App Group unavailable: skip sandbox token probes.")
            lines.append("Check signing and the App Group entitlement before further testing.")
            return lines.joined(separator: "\n")
        }

        for (name, path) in [
            ("App bundle root", appBundleRoot),
            ("App data root", appDataRoot),
            ("Internal daemon root", daemonRoot)
        ] {
            lines.append("[\(name)]")
            lines.append("Path: \(path)")
            let result = probe(path: path, group: appGroup)
            lines.append(contentsOf: result.lines)

            if path == appBundleRoot {
                lines.append(contentsOf: inspectSamples(root: path,
                                                        group: appGroup,
                                                        maximum: 3,
                                                        inspectBundle: true))
            } else if path == appDataRoot {
                // The parent often cannot open, even when individual containers can.
                lines.append(contentsOf: inspectSamples(root: path,
                                                        group: appGroup,
                                                        maximum: 2,
                                                        inspectBundle: false))
            }
            if let handle = result.handle {
                worse_query_release(handle)
            }
            lines.append("")
        }

        lines.append("Interpretation:")
        lines.append("- Code -6 means a sandbox extension token was not returned.")
        lines.append("- Trying alternate flags is diagnostic, not a guaranteed bypass.")
        lines.append("- App bundle paths found by pathleak may still be inaccessible.")
        lines.append("- A token does not imply that a directory can actually open.")
        lines.append("- An absent xattr does not prove that the three-app limit was bypassed.")
        lines.append("- Installed bundles, ownership, xattrs and signing were not modified.")
        lines.append("Side effect: worse_query recreates Caches inside Erosion's own App Group.")
        return lines.joined(separator: "\n")
    }

    private static func openStatus(_ path: String) -> String {
        let fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        if fd >= 0 {
            close(fd)
            return "opened"
        }
        let code = errno
        return "denied (errno \(code): \(String(cString: strerror(code))))"
    }

    /// Request a sandbox extension in both supported modes. An issued token
    /// is not treated as success unless an actual directory open succeeds.
    /// Release the handle only after the open test.
    private static func probe(path: String, group: String) -> (lines: [String], opened: Bool, handle: Int64?) {
        var lines: [String] = []
        let before = openStatus(path)
        lines.append("Directory open BEFORE grant: \(before)")

        if before == "opened" {
            lines.append("Already accessible; sandbox query not needed.")
            return (lines, true, nil)
        }

        for (name, alternate) in [("standard", false), ("alternate", true)] {
            let handle = worse_query(path, group, alternate, false)
            let after = openStatus(path)
            lines.append("\(name) flags: \(handle >= 0 ? "token issued" : "error \(handle)"); open: \(after)")
            if after == "opened" {
                // Keep the sandbox grant alive for callers reading directory contents.
                return (lines, true, handle >= 0 ? handle : nil)
            }
            if handle >= 0 {
                worse_query_release(handle)
            }
        }
        return (lines, false, nil)
    }

    private static func inspectSamples(
        root: String,
        group: String,
        maximum: Int,
        inspectBundle: Bool
    ) -> [String] {
        var results: [String] = []
        let listed = (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []
        let paths: [String]
        if !listed.isEmpty {
            results.append("Discovery: directory listing")
            paths = listed.map { root + "/" + $0 }
        } else {
            results.append("Discovery: pathleak fallback (may be slow)")
            paths = FSHandlers().getDirPaths(root)
        }

        // Limit probes to immediate children. Do not include UUIDs in the report.
        let normalizedRoot = URL(fileURLWithPath: root).standardizedFileURL.path
        let containers = Array(Set(paths.map {
            URL(fileURLWithPath: $0).standardizedFileURL.path
        }.filter {
            URL(fileURLWithPath: $0).deletingLastPathComponent().path == normalizedRoot
        })).sorted()

        results.append("Container candidates discovered: \(containers.count)")
        if containers.isEmpty {
            results.append("No candidates found; cannot infer container accessibility.")
            return results
        }

        for (index, container) in containers.prefix(maximum).enumerated() {
            results.append("Sample \(index + 1):")
            let access = probe(path: container, group: group)
            results.append(contentsOf: access.lines.map { "  " + $0 })

            if inspectBundle && access.opened,
               let names = try? FileManager.default.contentsOfDirectory(atPath: container),
               let appName = names.first(where: { $0.hasSuffix(".app") }) {
                let appPath = container + "/" + appName
                let appAccess = probe(path: appPath, group: group)
                results.append(contentsOf: appAccess.lines.map { "  .app " + $0 })
                if appAccess.opened {
                    results.append("  \(bundleMetadata(at: appPath))")
                } else {
                    results.append("  Bundle metadata not accessible.")
                }
                if let handle = appAccess.handle {
                    worse_query_release(handle)
                }
            } else if inspectBundle {
                results.append("  No .app directory could be enumerated.")
            }
            if let handle = access.handle {
                worse_query_release(handle)
            }
        }

        return results
    }

    private static func bundleMetadata(at path: String) -> String {
        var fileStat = stat()
        let statResult = path.withCString { lstat($0, &fileStat) }
        let owner = statResult == 0
            ? "UID \(fileStat.st_uid), GID \(fileStat.st_gid)"
            : "owner unreadable (errno \(errno))"

        errno = 0
        let length = getxattr(path, attribute, nil, 0, 0, 0)
        let xattrState: String
        if length >= 0 {
            xattrState = "present (\(length) bytes)"
        } else {
            let code = errno
            xattrState = code == ENOATTR
                ? "absent"
                : "unreadable (errno \(code))"
        }

        var profileStat = stat()
        let hasProfile = (path + "/embedded.mobileprovision").withCString {
            lstat($0, &profileStat) == 0
        }

        return "Owner: \(owner); embedded.mobileprovision: \(hasProfile ? "present" : "not visible"); free-profile xattr: \(xattrState)"
    }
}
