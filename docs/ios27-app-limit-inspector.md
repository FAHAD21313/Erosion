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
- Whether app bundle, app data, and internal daemon directory roots open before
  and after requesting a `worse_query` sandbox extension.
- Whether bundle containers can be discovered by directory listing or the
  project's existing `pathleak` path enumeration routine.
- For up to three sample app bundles, whether a sandbox token is issued,
  whether the container can actually be opened, the visible POSIX owner,
  whether `embedded.mobileprovision` is visible, and the *presence or
  absence* (not the value) of `com.apple.installd.validatedByFreeProfile`.

### How to read the results

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
  `Library/Caches` **inside Erosion's own App Group** to request a sandbox
  extension. This is an existing exploit side effect, so the scan is not
  literally free of all local writes.
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
