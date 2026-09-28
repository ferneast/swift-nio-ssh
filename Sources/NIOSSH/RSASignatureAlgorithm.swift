//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// The signature algorithm an RSA key signs with (RFC 8332).
///
/// An RSA key has one wire format, `ssh-rsa`, and several signature algorithms that
/// differ in the hash they use. The SHA-1 algorithm that shares the key format's name
/// is deliberately absent: it is neither offered nor accepted.
public enum RSASignatureAlgorithm: Hashable, Sendable, CaseIterable {
    /// `rsa-sha2-512`
    case sha512

    /// `rsa-sha2-256`
    case sha256

    /// The algorithm name as it appears on the wire.
    public var algorithmName: String {
        switch self {
        case .sha512: return "rsa-sha2-512"
        case .sha256: return "rsa-sha2-256"
        }
    }

    internal var wireBytes: String.UTF8View { self.algorithmName.utf8 }

    /// Returns `nil` for any name that is not an RSA signature algorithm this library supports.
    public init?<Bytes: Collection>(algorithmName bytes: Bytes) where Bytes.Element == UInt8 {
        guard let match = Self.allCases.first(where: { bytes.elementsEqual($0.wireBytes) }) else {
            return nil
        }
        self = match
    }
}
