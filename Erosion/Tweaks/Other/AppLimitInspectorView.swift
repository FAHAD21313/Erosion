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
            "Erosion / App Limit Inspector (read-only)",
            "Date: \(ISO8601DateFormatter().string(from: Date()))",
            "OS: \(ProcessInfo.processInfo.operatingSystemVersionString)",
            "Build: \(buildNumber())",
            "Test: iOS 27 sandbox and installed-bundle metadata",
            ""
        ]

        let appGroup = wq.getAppGroup()
        let groupAvailable = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroup
        ) != nil
        lines.append("App Group entitlement/container: \(groupAvailable ? "available" : "unavailable")")
        lines.append("No Apple ID, provisioning profile or app contents are exported.")
        lines.append("")

        for (name, path) in [
            ("App bundle root", appBundleRoot),
            ("App data root (comparison)", appDataRoot),
            ("Internal daemon root (comparison)", daemonRoot)
        ] {
            lines.append("[\(name)]")
            lines.append("Path: \(path)")
            let before = openStatus(path)
            lines.append("Directory open BEFORE grant: \(before)")
            let handle = worse_query(path, appGroup, false, false)
            lines.append("worse_query result: \(handle >= 0 ? "token acquired" : "error \(handle)")")
            lines.append("Directory open AFTER grant: \(openStatus(path))")

            if path == appBundleRoot {
                lines.append(contentsOf: inspectBundleSamples(root: path))
            }

            if handle >= 0 {
                worse_query_release(handle)
            }
            lines.append("")
        }

        lines.append("Interpretation:")
        lines.append("- A sandbox token does not imply the directory can be opened.")
        lines.append("- POSIX ownership restrictions still apply after a sandbox grant.")
        lines.append("- An absent xattr is not proof of a successful three-app bypass.")
        lines.append("- No changes to installed bundles, xattrs, ownership or signing were attempted.")
        lines.append("Note: worse_query temporarily recreates Library/Caches inside Erosion's own App Group.")
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

    private static func inspectBundleSamples(root: String) -> [String] {
        var results: [String] = []

        let listed = (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []
        let paths: [String]
        if !listed.isEmpty {
            results.append("Container discovery: directory listing")
            paths = listed.map { root + "/" + $0 }
        } else {
            results.append("Container discovery: pathleak fallback (may be slow)")
            paths = FSHandlers().getDirPaths(root)
        }

        // Only immediate child containers are eligible. Never recurse into app data.
        let normalizedRoot = URL(fileURLWithPath: root).standardizedFileURL.path
        let containers = Array(Set(paths.map {
            URL(fileURLWithPath: $0).standardizedFileURL.path
        }.filter {
            URL(fileURLWithPath: $0).deletingLastPathComponent().path == normalizedRoot
        })).sorted()

        results.append("Container candidates discovered: \(containers.count)")
        if containers.isEmpty {
            results.append("No bundle containers accessible for a metadata sample.")
            return results
        }

        for (index, container) in containers.prefix(3).enumerated() {
            let handle = worse_query(container, wq.getAppGroup(), false, false)
            let containerStatus = openStatus(container)
            results.append("Sample \(index + 1): token \(handle >= 0 ? "issued" : "error \(handle)"), directory \(containerStatus)")

            if let names = try? FileManager.default.contentsOfDirectory(atPath: container),
               let appName = names.first(where: { $0.hasSuffix(".app") }) {
                let appPath = container + "/" + appName
                let appHandle = worse_query(appPath, wq.getAppGroup(), false, false)
                results.append("  .app token: \(appHandle >= 0 ? "issued" : "error \(appHandle)")")
                results.append("  \(bundleMetadata(at: appPath))")
                if appHandle >= 0 {
                    worse_query_release(appHandle)
                }
            } else {
                results.append("  .app contents inaccessible or not found")
            }

            if handle >= 0 {
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
