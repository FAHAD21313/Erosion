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
    @State private var isClassifying = false
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
                .disabled(isRunning || isClassifying)

                Button {
                    runClassification()
                } label: {
                    Label(isClassifying ? "Classifying daemon containers…" : "Identify Daemon Containers (extended)", systemImage: "list.bullet.rectangle")
                }
                .disabled(isRunning || isClassifying)

                Text("Optional: checks identifiers on up to 35 daemon data containers. It may take time and causes repeated worse_query cache swaps inside Erosion's own App Group.")
                    .font(.footnote)
                    .foregroundStyle(.secondary)

                if isRunning || isClassifying {
                    ProgressView("Running read-only diagnostics…")
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
        guard !isRunning && !isClassifying else { return }
        isRunning = true

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                AppLimitInspector.generateReport()
            }.value
            report = result
            isRunning = false
        }
    }

    private func runClassification() {
        guard !isRunning && !isClassifying else { return }
        isClassifying = true

        Task {
            let result = await Task.detached(priority: .userInitiated) {
                AppLimitInspector.classifyDaemonContainers()
            }.value
            report = report.isEmpty ? result : report + "\n\n" + result
            isClassifying = false
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
            "Erosion / App Limit Inspector v4 (read-only)",
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
            } else if path == daemonRoot {
                // As with app data, test actual daemon-container children;
                // a failed query for the parent is not a conclusive result.
                lines.append(contentsOf: inspectSamples(root: path,
                                                        group: appGroup,
                                                        maximum: 3,
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
        lines.append("- Access to individual daemon data containers does not imply installd access.")
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

    /// Extended, opt-in scan of daemon DATA containers. No app files,
    /// installation records, or arbitrary daemon file contents are read.
    static func classifyDaemonContainers() -> String {
        var lines: [String] = [
            "Erosion / InternalDaemon Classification (read-only)",
            "Date: \(ISO8601DateFormatter().string(from: Date()))",
            "OS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "Scope: daemon container metadata only (up to 35 candidates)",
            ""
        ]
        let appGroup = wq.getAppGroup()
        guard FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroup) != nil else {
            lines.append("App Group unavailable; scan not started.")
            return lines.joined(separator: "\n")
        }

        let root = daemonRoot
        let paths: [String]
        if let listed = try? FileManager.default.contentsOfDirectory(atPath: root) {
            paths = listed.map { root + "/" + $0 }
            lines.append("Discovery method: directory listing")
        } else {
            paths = FSHandlers().getDirPaths(root)
            lines.append("Discovery method: pathleak")
        }

        let normalizedRoot = URL(fileURLWithPath: root).standardizedFileURL.path
        let children = Array(Set(paths.map {
            URL(fileURLWithPath: $0).standardizedFileURL.path
        }.filter {
            URL(fileURLWithPath: $0).deletingLastPathComponent().path == normalizedRoot
        })).sorted()
        let sample = Array(children.prefix(35))
        lines.append("Candidates found: \(children.count)")
        lines.append("Candidates scanned: \(sample.count)")

        var accessible = 0
        var labeled = 0
        var appleLabels = 0
        var rootOwned = 0
        var mobileOwned = 0
        var otherOwned = 0
        var relevant: [String] = []
        let installerKeywords = ["installd", "install", "appstored", "appstore", "launchservices", "mobilecontainer", "lsd"]

        for container in sample {
            let result = probe(path: container, group: appGroup)
            if result.opened {
                accessible += 1
                var itemStat = stat()
                if container.withCString({ lstat($0, &itemStat) }) == 0 {
                    if itemStat.st_uid == 0 {
                        rootOwned += 1
                    } else if itemStat.st_uid == 501 {
                        mobileOwned += 1
                    } else {
                        otherOwned += 1
                    }
                }

                if let identifier = containerIdentifier(path: container) {
                    labeled += 1
                    if identifier.hasPrefix("com.apple.") {
                        appleLabels += 1
                        let lowered = identifier.lowercased()
                        if installerKeywords.contains(where: { lowered.contains($0) }) {
                            // Only Apple service labels; never UUIDs or application IDs.
                            relevant.append(identifier)
                        }
                    }
                }
            }
            if let handle = result.handle {
                worse_query_release(handle)
            }
        }

        lines.append("Containers opened: \(accessible) / \(sample.count)")
        lines.append("Readable container identifiers: \(labeled)")
        lines.append("Apple service identifiers: \(appleLabels)")
        lines.append("Owner UID 0 (root): \(rootOwned)")
        lines.append("Owner UID 501 (mobile): \(mobileOwned)")
        lines.append("Other owners: \(otherOwned)")
        lines.append("Installer-related Apple identifier matches: \(relevant.count)")
        for identifier in Set(relevant).sorted() {
            lines.append("  Apple service: \(identifier)")
        }
        lines.append("")
        lines.append("Limitations:")
        lines.append("- InternalDaemon DATA access is not access to the installd process.")
        lines.append("- A matching name is only an identifier clue, not proof of any control.")
        lines.append("- No matching identifiers does not prove installer state is absent.")
        lines.append("- No app bundles, signing, xattrs or installation data were modified.")
        lines.append("- Token queries recreate Caches in Erosion's own App Group.")
        return lines.joined(separator: "\n")
    }

    private static func containerIdentifier(path: String) -> String? {
        var buffer = [CChar](repeating: 0, count: 512)
        let count = getxattr(path, "com.apple.containermanager.identifier", &buffer, 511, 0, 0)
        guard count > 0 && count <= 511 else { return nil }
        buffer[Int(count)] = 0
        guard let identifier = String(validatingUTF8: buffer), !identifier.isEmpty else { return nil }
        // Prevent arbitrary strings from appearing in the exported report.
        let acceptable = identifier.utf8.allSatisfy { byte in
            (byte >= 65 && byte <= 90) || (byte >= 97 && byte <= 122) ||
            (byte >= 48 && byte <= 57) || byte == 46 || byte == 45 || byte == 95
        }
        return acceptable ? identifier : nil
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
