# iOS 27 App Limit Inspector (research)

This is a **diagnostic tool, not a three-app bypass**. It is the first research step for
investigating whether Erosion's `worse_query` sandbox escape can help understand the
free Apple Developer account's three-installed-app limit.

## Using the inspector

1. Build and sideload this fork with a working App Group entitlement, as required by Erosion.
2. Open **Tweaks → System → App Limit Inspector (iOS 27)**.
3. Select **Run Read-Only Scan**. Bundle discovery via `pathleak` may take time.
4. Share the displayed report manually if you want to compare results across iOS versions.

The report contains OS/build metadata, fixed filesystem paths, and anonymized
sample numbers. It intentionally omits App Group IDs, container UUIDs, app names,
bundle identifiers, provisioning profile contents, and account credentials.

## What it measures

- Whether an existing App Group container is available to Erosion.
- Whether app bundle, app data, and internal daemon directory roots open before and after requesting sandbox extensions with both standard and alternate `worse_query` flags. The alternate mode is tried only if the first request does not grant usable directory access.
- Whether app bundle, app data, and internal-daemon containers can be discovered by directory listing or the project's existing `pathleak` enumeration routine. It probes up to three bundle containers, two app-data containers, and three daemon containers individually, because a parent may be inaccessible even if its children are not.
- For up to three sample app bundles, whether a sandbox token is issued,
  whether the container can actually be opened, the visible POSIX owner,
  whether `embedded.mobileprovision` is visible, and the *presence or
  absence* (not the value) of `com.apple.installd.validatedByFreeProfile`.

### How to read the results

If you see `error -6`, `copy_sandbox_token` returned no extension token. This is not evidence that a valid extension was consumed and then denied; the diagnostic compares both supported query flag modes to distinguish cases.

A token being issued **does not** mean that the target is readable or writable.
A POSIX denial may remain even after a sandbox extension has been consumed.
The absence of the free-profile extended attribute **does not** establish that
an installed app has stopped counting against the three-app limit.
This prototype does not enumerate the full set of installed apps and cannot
confirm that a fourth independently installed IPA is possible.

If the bundle root is blocked and individual candidate paths are blocked too,
the next research step is to characterize the boundary, not to assume a
`removexattr()` call would succeed.

## Safety and scope

- No writes are performed to *installed app bundles*, extended attributes,
  provisioning profiles, ownership, or installation databases.
- The existing `worse_query` implementation temporarily removes/recreates
  `Library/Caches` **inside Erosion's own App Group** on each sandbox query.
  It may delete data cached there. This is an existing exploit side effect,
  so the scan is not literally free of all local writes. Run only on a device
  with a recent backup.
- The project's `pathleak` helper creates and removes a small temporary file
  inside Erosion's own temporary directory.
- No telemetry or automatic uploads are included. Sharing is user initiated.
- Back up your device before testing experimental iOS modifications.
- No assertion is made that this behavior works on a particular iOS 27 build.
  Test results are device- and OS-specific.

## Implementation

- `Erosion/Tweaks/Other/AppLimitInspectorView.swift`: inspector UI and probes.
- `Erosion/Tweaks/TweaksView.swift`: navigation entry point.

The project uses Xcode file-system-synchronized groups, so the new Swift
file is picked up without manually editing the Xcode project file.

Sources for the motivation:
- [Lara's 3 App Bypass implementation](https://github.com/rooootdev/lara/blob/main/lara/views/tweaks/AppsView.swift)
- [Lara's APFS ownership code](https://github.com/rooootdev/lara/blob/main/lara/kexploit/pe/apfs.m)
- [WQ Files](https://github.com/kolbicz/WQFiles)
- [worse_query](https://github.com/forcequitOS/worse_query)

## iOS 27.0.1 findings (initial report, 2026-11-13)

A first on-device report (build 24A446) showed an App Group container, 13 app
bundle container paths discovered by `pathleak`, and `worse_query` code `-6`
for all root and sampled bundle requests using standard flags. None of the
app bundles opened. This **does not** establish whether an alternate flag or
an individually targeted app-data container will work; the updated inspector
now tests both variants. Do not claim that finding paths grants access.

## iOS 27.0.1 second report (2026-11-13, build 24A446)

A second on-device report tested both query flag sets. It discovered 13
application bundles and 317 app-data candidates. Both sampled app-data
children acquired tokens with standard flags and their directories opened.
The three tested application-bundle containers still returned `-6` for both
flag sets, and their directories remained inaccessible. A token for the
parent paths was not issued. The App Group and exploit do work for at least
some *individual* data containers. v3 extends the same individual-container
test to InternalDaemon children; this can check daemon-container reachability,
not installer service control or a three-app bypass.
