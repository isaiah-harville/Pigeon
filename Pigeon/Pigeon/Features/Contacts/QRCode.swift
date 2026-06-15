//
//  QRCode.swift
//  Pigeon
//
//  Renders a string into a QR code image for in-person identity exchange.
//

import SwiftUI
import CoreImage
import CoreImage.CIFilterBuiltins

enum QRCode {
    private static let context = CIContext()

    /// Generates a crisp QR `CGImage` encoding `string`, or `nil` on failure.
    static func cgImage(from string: String) -> CGImage? {
        let filter = CIFilter.qrCodeGenerator()
        filter.message = Data(string.utf8)
        filter.correctionLevel = "M"
        guard let output = filter.outputImage else { return nil }
        // Scale up so the code is sharp when displayed.
        let scaled = output.transformed(by: CGAffineTransform(scaleX: 12, y: 12))
        return context.createCGImage(scaled, from: scaled.extent)
    }

    /// A SwiftUI view of the QR code for `string`.
    @ViewBuilder
    static func image(from string: String) -> some View {
        if let cgImage = cgImage(from: string) {
            Image(decorative: cgImage, scale: 1.0)
                .interpolation(.none)
                .resizable()
                .scaledToFit()
        } else {
            Image(systemName: "xmark.octagon")
        }
    }
}
