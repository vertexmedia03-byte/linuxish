# HelloWorld iPad app

This is a minimal UIKit iPad app. The screen is implemented in Objective-C++, and the greeting text is returned by a C++ function.

## Build on a Mac

1. Install Xcode and open `HelloWorld.xcodeproj`.
2. Select the **HelloWorld** scheme and an iPad simulator to run it without signing, or select a connected iPad and configure signing in the target's **Signing & Capabilities** settings.
3. To create a signed IPA, select **Any iOS Device (arm64)** and choose **Product > Archive**. In the Organizer, choose **Distribute App** and follow the signing/export prompts.

## Build an unsigned IPA with GitHub Actions

The **Build unsigned iOS IPA** workflow builds the app without code signing, packages it as `HelloWorld.ipa`, and uploads it as the `HelloWorld-unsigned-ipa` artifact. It runs on pushes and pull requests to `main`, or can be started manually from the Actions tab with **Run workflow**.

Download the artifact from the completed workflow run. The IPA is unsigned and intended for installation with TrollStore on a compatible device and iOS version; it is not suitable for App Store or ordinary device installation.

For command-line archive and export, replace `YOUR_TEAM_ID` in `ExportOptions.plist` with your Apple Developer team ID, then replace `TEAM_ID` below with the same value:

```sh
xcodebuild -project HelloWorld.xcodeproj \
  -scheme HelloWorld \
  -configuration Release \
  -destination 'generic/platform=iOS' \
  -archivePath build/HelloWorld.xcarchive \
  DEVELOPMENT_TEAM=TEAM_ID \
  archive

xcodebuild -exportArchive \
  -archivePath build/HelloWorld.xcarchive \
  -exportPath build/export \
  -exportOptionsPlist ExportOptions.plist
```

The included export settings create a development-signed IPA for registered devices. For TestFlight or App Store distribution, choose the corresponding distribution method in Xcode Organizer or change the `method` in `ExportOptions.plist` to the method supported by your Xcode version and account. The exported `.ipa` will be in `build/export`.
