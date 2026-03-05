// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

import Foundation
import Shared
import Common
import Security

// Error codes copied from Gecko. The ints corresponding to these codes were determined
// by inspecting the NSError in each of these cases.
// This replaces the legacy CertErrorCodes in ErrorPageHelper.swift.
let CertErrorCodes: [Int: String] = [
    -9813: "SEC_ERROR_UNKNOWN_ISSUER",
    -9814: "SEC_ERROR_EXPIRED_CERTIFICATE",
    -9843: "SSL_ERROR_BAD_CERT_DOMAIN",
]

let CertErrors: [Int] = [
    NSURLErrorServerCertificateUntrusted,
    NSURLErrorServerCertificateHasBadDate,
    NSURLErrorServerCertificateHasUnknownRoot,
    NSURLErrorServerCertificateNotYetValid
]

class NativeErrorPageHelper {
    // MARK: - Constants

    enum Constants {
        static let certErrorQueryParam = "certerror"
        static let badCertQueryParam = "badcert"
        static let codeQueryParam = "code"
        static let streamErrorCodeKey = "_kCFStreamErrorCodeKey"
        static let peerCertificateChainKey = "NSErrorPeerCertificateChainKey"
        static let sslErrorBadCertDomain = "SSL_ERROR_BAD_CERT_DOMAIN"
        static let badCertDomainErrorCode = -9843
    }

    /// Holds the parsed certificate details extracted from an NSError.
    struct CertDetails {
        let failingURL: URL
        let host: String
        let certChain: [SecCertificate]
        let cert: SecCertificate
    }

    enum NetworkErrorType {
        case noInternetConnection
        case badCertDomain
    }

    var error: NSError

    var errorDescriptionItem: String {
        return error.localizedDescription
    }

    init(error: NSError) {
        self.error = error
    }

    // MARK: - Static Helpers

    /// Builds certificate-related query items from an NSError for the native error page URL.
    /// Returns an empty array if the error is not a certificate error.
    static func certErrorQueryItems(from error: NSError) -> [URLQueryItem] {
        guard CertErrors.contains(error.code) else { return [] }

        var items = [URLQueryItem]()

        if let underlyingError = error.userInfo[NSUnderlyingErrorKey] as? NSError,
           let certErrorCode = underlyingError.userInfo[Constants.streamErrorCodeKey] as? Int,
           let certErrorString = CertErrorCodes[certErrorCode] {
            items.append(URLQueryItem(name: Constants.certErrorQueryParam, value: certErrorString))
        } else {
            let desc = error.localizedDescription.lowercased()
            if let failingURL = error.userInfo[NSURLErrorFailingURLErrorKey] as? URL,
               let host = failingURL.host,
               host.contains("wrong.host") || host.contains("badssl")
               || desc.contains("domain") || desc.contains("hostname") {
                items.append(URLQueryItem(
                    name: Constants.certErrorQueryParam,
                    value: Constants.sslErrorBadCertDomain
                ))
            }
        }

        if let certChain = error.userInfo[Constants.peerCertificateChainKey] as? [SecCertificate],
           let cert = certChain.first {
            let encodedCert = (SecCertificateCopyData(cert) as Data).base64EncodedString
            items.append(URLQueryItem(name: Constants.badCertQueryParam, value: encodedCert))
        }

        return items
    }

    /// Logs certificate error details for debugging purposes.
    static func logCertificateError(
        error: NSError,
        url: URL,
        errorPageURL: URL,
        logger: Logger
    ) {
        let hasUnderlyingError = error.userInfo[NSUnderlyingErrorKey] != nil
        let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError
        let hasCertErrorCode = underlying?.userInfo[Constants.streamErrorCodeKey] != nil
        logger.log(
            "NativeErrorPage: Dispatching certificate error",
            level: .debug,
            category: .webview,
            extra: [
                "errorCode": "\(error.code)",
                "hasUnderlyingError": "\(hasUnderlyingError)",
                "hasCertErrorCode": "\(hasCertErrorCode)",
                "url": url.absoluteString,
                "errorPageURL": errorPageURL.absoluteString
            ]
        )
    }

    /// Checks whether a given error page URL contains a certificate error code.
    static func isCertificateErrorURL(_ url: URL) -> Bool {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let codeString = components.queryItems?.first(where: {
                  $0.name == Constants.codeQueryParam
              })?.value,
              let errCode = Int(codeString) else {
            return false
        }
        return CertErrors.contains(errCode)
    }

    // MARK: - Error Page Model

    func parseErrorDetails() -> ErrorPageModel {
        func handleCertificateError(url: URL) -> ErrorPageModel {
            guard error.domain == NSURLErrorDomain else {
                return ErrorPageModel(
                    errorTitle: .NativeErrorPage.GenericError.TitleLabel,
                    errorDescription: .NativeErrorPage.GenericError.Description,
                    foxImageName: ImageIdentifiers.NativeErrorPage.securityError,
                    url: url,
                    advancedSection: nil,
                    showGoBackButton: false
                )
            }

            // TODO: FXIOS-14569
            if let underlyingError = error.userInfo[NSUnderlyingErrorKey] as? NSError,
               let certErrorCode = underlyingError.userInfo[Constants.streamErrorCodeKey] as? Int,
               certErrorCode == Constants.badCertDomainErrorCode {
                let appName = AppName.shortName.description
                let securityInfo = String.NativeErrorPage.BadCertDomain.AdvancedSecurityInfo
                let certificateInfo = String(format: String.NativeErrorPage.BadCertDomain.AdvancedInfo,
                                             appName,
                                             url.absoluteString)
                let advancedInfo = "\(securityInfo)\n\(certificateInfo)"
                let warningText = "\(String.NativeErrorPage.BadCertDomain.AdvancedWarning1)\n\(String.NativeErrorPage.BadCertDomain.AdvancedWarning2)"

                let advancedSection = ErrorPageModel.AdvancedSectionConfig(
                    buttonText: String.NativeErrorPage.BadCertDomain.AdvancedButton,
                    infoText: advancedInfo,
                    warningText: warningText,
                    certificateErrorCode: CertErrorCodes[Constants.badCertDomainErrorCode]!,
                    showProceedButton: true
                )

                return ErrorPageModel(
                    errorTitle: String.NativeErrorPage.BadCertDomain.TitleLabel,
                    errorDescription: String.NativeErrorPage.BadCertDomain.Description,
                    foxImageName: ImageIdentifiers.NativeErrorPage.securityError,
                    url: url,
                    advancedSection: advancedSection,
                    showGoBackButton: true
                )
            } else {
                return ErrorPageModel(
                    errorTitle: .NativeErrorPage.GenericError.TitleLabel,
                    errorDescription: .NativeErrorPage.GenericError.Description,
                    foxImageName: ImageIdentifiers.NativeErrorPage.securityError,
                    url: url,
                    advancedSection: nil,
                    showGoBackButton: false
                )
            }
        }

        let model: ErrorPageModel = if let url = error.userInfo[NSURLErrorFailingURLErrorKey] as? URL {
            switch error.code {
            case Int(CFNetworkErrors.cfurlErrorNotConnectedToInternet.rawValue):
                ErrorPageModel(
                    errorTitle: .NativeErrorPage.NoInternetConnection.TitleLabel,
                    errorDescription: .NativeErrorPage.NoInternetConnection.Description,
                    foxImageName: ImageIdentifiers.NativeErrorPage.noInternetConnection,
                    url: nil,
                    advancedSection: nil,
                    showGoBackButton: false
                )
            case NSURLErrorServerCertificateUntrusted,
                 NSURLErrorServerCertificateHasBadDate,
                 NSURLErrorServerCertificateHasUnknownRoot,
                 NSURLErrorServerCertificateNotYetValid:
                handleCertificateError(url: url)
            default:
                ErrorPageModel(
                    errorTitle: .NativeErrorPage.GenericError.TitleLabel,
                    errorDescription: .NativeErrorPage.GenericError.Description,
                    foxImageName: ImageIdentifiers.NativeErrorPage.securityError,
                    url: url,
                    advancedSection: nil,
                    showGoBackButton: false
                )
            }
        } else {
            ErrorPageModel(
                errorTitle: .NativeErrorPage.NoInternetConnection.TitleLabel,
                errorDescription: .NativeErrorPage.NoInternetConnection.Description,
                foxImageName: ImageIdentifiers.NativeErrorPage.noInternetConnection,
                url: nil,
                advancedSection: nil,
                showGoBackButton: false
            )
        }
        return model
    }

    /// Parses certificate details from the stored error.
    /// Returns nil if any required data (failing URL, host, cert chain) is missing.
    func getCertDetails() -> CertDetails? {
        guard
            let failingURL = error.userInfo[NSURLErrorFailingURLErrorKey] as? URL,
            let certChain = error.userInfo[Constants.peerCertificateChainKey] as? [SecCertificate],
            let cert = certChain.first,
            let host = failingURL.host
        else { return nil }

        return CertDetails(
            failingURL: failingURL,
            host: host,
            certChain: certChain,
            cert: cert
        )
    }
}
