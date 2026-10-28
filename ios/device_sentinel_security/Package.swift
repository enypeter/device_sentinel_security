// swift-tools-version: 5.9
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "device_sentinel_security",
    platforms: [
        .iOS("13.0")
    ],
    products: [
        .library(name: "device-sentinel-security", targets: ["device_sentinel_security"])
    ],
    dependencies: [
        .package(name: "FlutterFramework", path: "../FlutterFramework")
    ],
    targets: [
        .target(
            name: "device_sentinel_security",
            dependencies: [
                .product(name: "FlutterFramework", package: "FlutterFramework")
            ],
            resources: [
                // No required-reason APIs and no data collection; shipped so
                // App Store privacy reports list the plugin explicitly.
                .process("PrivacyInfo.xcprivacy"),
            ]
        )
    ]
)
