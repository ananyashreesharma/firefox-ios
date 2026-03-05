// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/

import XCTest

@testable import Client

final class NativeErrorPageHelperTests: XCTestCase {
    // MARK: - certErrorQueryItems

    func testCertErrorQueryItems_nonCertError_returnsEmpty() {
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorNotConnectedToInternet,
            userInfo: [NSURLErrorFailingURLErrorKey: URL(string: "https://example.com")!]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        XCTAssertTrue(items.isEmpty)
    }

    func testCertErrorQueryItems_certUntrusted_withUnderlyingError_returnsCertErrorItem() {
        let underlyingError = NSError(
            domain: "NSOSStatusErrorDomain",
            code: -9807,
            userInfo: ["_kCFStreamErrorCodeKey": -9813]
        )
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateUntrusted,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://example.com")!,
                NSUnderlyingErrorKey: underlyingError
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        let certErrorItem = items.first(where: { $0.name == NativeErrorPageHelper.Constants.certErrorQueryParam })
        XCTAssertNotNil(certErrorItem)
        XCTAssertEqual(certErrorItem?.value, "SEC_ERROR_UNKNOWN_ISSUER")
    }

    func testCertErrorQueryItems_certBadDate_withUnderlyingExpiredCert_returnsExpiredCertItem() {
        let underlyingError = NSError(
            domain: "NSOSStatusErrorDomain",
            code: -9807,
            userInfo: ["_kCFStreamErrorCodeKey": -9814]
        )
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateHasBadDate,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://expired.example.com")!,
                NSUnderlyingErrorKey: underlyingError
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        let certErrorItem = items.first(where: { $0.name == NativeErrorPageHelper.Constants.certErrorQueryParam })
        XCTAssertNotNil(certErrorItem)
        XCTAssertEqual(certErrorItem?.value, "SEC_ERROR_EXPIRED_CERTIFICATE")
    }

    func testCertErrorQueryItems_certBadDomain_withUnderlyingError_returnsBadDomainItem() {
        let underlyingError = NSError(
            domain: "NSOSStatusErrorDomain",
            code: -9807,
            userInfo: ["_kCFStreamErrorCodeKey": -9843]
        )
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateUntrusted,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://wrong.host.badssl.com")!,
                NSUnderlyingErrorKey: underlyingError
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        let certErrorItem = items.first(where: { $0.name == NativeErrorPageHelper.Constants.certErrorQueryParam })
        XCTAssertNotNil(certErrorItem)
        XCTAssertEqual(certErrorItem?.value, "SSL_ERROR_BAD_CERT_DOMAIN")
    }

    func testCertErrorQueryItems_certError_withoutUnderlyingError_infersDomainFromHost() {
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateUntrusted,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://wrong.host.badssl.com")!,
                NSLocalizedDescriptionKey: "The certificate for this server is invalid."
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        let certErrorItem = items.first(where: { $0.name == NativeErrorPageHelper.Constants.certErrorQueryParam })
        XCTAssertNotNil(certErrorItem)
        XCTAssertEqual(certErrorItem?.value, NativeErrorPageHelper.Constants.sslErrorBadCertDomain)
    }

    func testCertErrorQueryItems_certError_noUnderlyingError_noMatchingHost_returnsNoCertErrorItem() {
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateUntrusted,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://example.com")!,
                NSLocalizedDescriptionKey: "The certificate for this server is invalid."
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        let certErrorItem = items.first(where: { $0.name == NativeErrorPageHelper.Constants.certErrorQueryParam })
        XCTAssertNil(certErrorItem)
    }

    func testCertErrorQueryItems_unknownRoot_returnsItems() {
        let underlyingError = NSError(
            domain: "NSOSStatusErrorDomain",
            code: -9807,
            userInfo: ["_kCFStreamErrorCodeKey": -9813]
        )
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateHasUnknownRoot,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://untrusted-root.example.com")!,
                NSUnderlyingErrorKey: underlyingError
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        XCTAssertFalse(items.isEmpty)
    }

    func testCertErrorQueryItems_notYetValid_returnsItems() {
        let underlyingError = NSError(
            domain: "NSOSStatusErrorDomain",
            code: -9807,
            userInfo: ["_kCFStreamErrorCodeKey": -9814]
        )
        let error = NSError(
            domain: NSURLErrorDomain,
            code: NSURLErrorServerCertificateNotYetValid,
            userInfo: [
                NSURLErrorFailingURLErrorKey: URL(string: "https://future-cert.example.com")!,
                NSUnderlyingErrorKey: underlyingError
            ]
        )
        let items = NativeErrorPageHelper.certErrorQueryItems(from: error)
        XCTAssertFalse(items.isEmpty)
    }

    // MARK: - isCertificateErrorURL

    func testIsCertificateErrorURL_withCertUntrustedCode_returnsTrue() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=\(NSURLErrorServerCertificateUntrusted)")!
        XCTAssertTrue(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withBadDateCode_returnsTrue() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=\(NSURLErrorServerCertificateHasBadDate)")!
        XCTAssertTrue(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withUnknownRootCode_returnsTrue() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=\(NSURLErrorServerCertificateHasUnknownRoot)")!
        XCTAssertTrue(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withNotYetValidCode_returnsTrue() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=\(NSURLErrorServerCertificateNotYetValid)")!
        XCTAssertTrue(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withNoInternetCode_returnsFalse() {
        let code = Int(CFNetworkErrors.cfurlErrorNotConnectedToInternet.rawValue)
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=\(code)")!
        XCTAssertFalse(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withNoCodeParam_returnsFalse() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com")!
        XCTAssertFalse(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withNonNumericCode_returnsFalse() {
        let url = URL(string: "internal://local/errorpage?url=https://example.com&code=abc")!
        XCTAssertFalse(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    func testIsCertificateErrorURL_withRegularURL_returnsFalse() {
        let url = URL(string: "https://www.mozilla.org")!
        XCTAssertFalse(NativeErrorPageHelper.isCertificateErrorURL(url))
    }

    // MARK: - Constants

    func testConstants_queryParamNames_areCorrect() {
        XCTAssertEqual(NativeErrorPageHelper.Constants.certErrorQueryParam, "certerror")
        XCTAssertEqual(NativeErrorPageHelper.Constants.badCertQueryParam, "badcert")
        XCTAssertEqual(NativeErrorPageHelper.Constants.codeQueryParam, "code")
        XCTAssertEqual(NativeErrorPageHelper.Constants.sslErrorBadCertDomain, "SSL_ERROR_BAD_CERT_DOMAIN")
    }
}
