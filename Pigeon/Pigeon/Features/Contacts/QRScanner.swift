//
//  QRScanner.swift
//  Pigeon
//
//  Camera-based QR scanning for in-person contact exchange.
//

import AVFoundation
import SwiftUI
import UIKit

/// A live camera view that reports decoded QR strings.
struct QRScanner: UIViewControllerRepresentable {
  /// Called with each decoded QR payload. Returns once the view appears; the
  /// parent typically dismisses on the first successful scan.
  let onScan: (String) -> Void

  func makeCoordinator() -> Coordinator { Coordinator(onScan: onScan) }

  func makeUIViewController(context: Context) -> ScannerViewController {
    let controller = ScannerViewController()
    controller.coordinator = context.coordinator
    return controller
  }

  func updateUIViewController(_: ScannerViewController, context _: Context) {}

  final class Coordinator: NSObject, AVCaptureMetadataOutputObjectsDelegate {
    private let onScan: (String) -> Void
    private var hasScanned = false

    init(onScan: @escaping (String) -> Void) { self.onScan = onScan }

    func metadataOutput(
      _: AVCaptureMetadataOutput,
      didOutput metadataObjects: [AVMetadataObject],
      from _: AVCaptureConnection
    ) {
      guard !hasScanned,
        let object = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
        object.type == .qr,
        let value = object.stringValue
      else { return }
      hasScanned = true
      onScan(value)
    }
  }
}

/// Hosts the capture session and preview layer.
final class ScannerViewController: UIViewController {
  weak var coordinator: QRScanner.Coordinator?
  private let session = AVCaptureSession()
  private var previewLayer: AVCaptureVideoPreviewLayer?

  override func viewDidLoad() {
    super.viewDidLoad()
    view.backgroundColor = .black
    configureSession()
  }

  private func configureSession() {
    guard let device = AVCaptureDevice.default(for: .video),
      let input = try? AVCaptureDeviceInput(device: device),
      session.canAddInput(input)
    else { return }
    session.addInput(input)

    let output = AVCaptureMetadataOutput()
    guard session.canAddOutput(output) else { return }
    session.addOutput(output)
    output.setMetadataObjectsDelegate(coordinator, queue: .main)
    output.metadataObjectTypes = [.qr]

    let preview = AVCaptureVideoPreviewLayer(session: session)
    preview.videoGravity = .resizeAspectFill
    preview.frame = view.layer.bounds
    view.layer.addSublayer(preview)
    previewLayer = preview

    Task.detached { [session] in session.startRunning() }
  }

  override func viewDidLayoutSubviews() {
    super.viewDidLayoutSubviews()
    previewLayer?.frame = view.layer.bounds
  }

  override func viewWillDisappear(_ animated: Bool) {
    super.viewWillDisappear(animated)
    if session.isRunning { session.stopRunning() }
  }
}
