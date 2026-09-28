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

import Crypto
import NIOCore
import NIOEmbedded
import NIOFoundationCompat
import XCTest
import _CryptoExtras

@testable import NIOSSH

final class RSAKeyTests: XCTestCase {
    /// Generating an RSA key is slow enough to share one between the tests.
    private static let rsaKey = try! _RSA.Signing.PrivateKey(keySize: .bits2048)

    private var rsaKey: _RSA.Signing.PrivateKey { Self.rsaKey }
    private var sshKey: NIOSSHPrivateKey { NIOSSHPrivateKey(rsaKey: Self.rsaKey) }

    /// The signature a server other than this library puts on the wire for `message`.
    private func wireSignature(over message: some DataProtocol, algorithm: RSASignatureAlgorithm) throws -> ByteBuffer {
        let signature: _RSA.Signing.RSASignature
        switch algorithm {
        case .sha512:
            signature = try self.rsaKey.signature(for: SHA512.hash(data: message), padding: .insecurePKCS1v1_5)
        case .sha256:
            signature = try self.rsaKey.signature(for: SHA256.hash(data: message), padding: .insecurePKCS1v1_5)
        }

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString(algorithm.algorithmName.utf8)
        buffer.writeSSHString(signature.rawRepresentation)
        return buffer
    }

    // MARK: - Host key signatures

    func testHostKeySignatureHashesTheExchangeHash() throws {
        // The exchange hash of a curve25519-sha256 key exchange is a SHA-256 digest. What
        // gets signed is that digest hashed again with the signature algorithm's own hash.
        let exchangeHash = SHA256.hash(data: Array("exchange".utf8))
        let signature = try self.sshKey.sign(digest: exchangeHash)

        guard case .rsa(let raw, let algorithm) = signature.backingSignature else {
            return XCTFail("Expected an RSA signature, got \(signature)")
        }
        XCTAssertEqual(algorithm, .sha512)
        XCTAssertTrue(
            self.rsaKey.publicKey.isValidSignature(
                raw,
                for: SHA512.hash(data: Data(exchangeHash)),
                padding: .insecurePKCS1v1_5
            )
        )
        XCTAssertTrue(self.sshKey.publicKey.isValidSignature(signature, for: exchangeHash))
    }

    func testVerifiesHostKeySignatureOfEitherAlgorithm() throws {
        let exchangeHash = SHA256.hash(data: Array("exchange".utf8))
        let otherExchangeHash = SHA256.hash(data: Array("another exchange".utf8))

        for algorithm in RSASignatureAlgorithm.allCases {
            var buffer = try self.wireSignature(over: Data(exchangeHash), algorithm: algorithm)
            let signature = try XCTUnwrap(buffer.readSSHSignature())

            XCTAssertEqual(signature.rsaSignatureAlgorithm, algorithm)
            XCTAssertTrue(self.sshKey.publicKey.isValidSignature(signature, for: exchangeHash), "\(algorithm)")
            XCTAssertFalse(self.sshKey.publicKey.isValidSignature(signature, for: otherExchangeHash), "\(algorithm)")
        }
    }

    func testRejectsSignatureOverTheExchangeHashItself() throws {
        // Signing the exchange hash as though it were already the digest to sign is a
        // different signature from the one the protocol asks for.
        let exchangeHash = SHA256.hash(data: Array("exchange".utf8))
        let raw = try self.rsaKey.signature(for: exchangeHash, padding: .insecurePKCS1v1_5)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("rsa-sha2-256".utf8)
        buffer.writeSSHString(raw.rawRepresentation)
        let signature = try XCTUnwrap(buffer.readSSHSignature())

        XCTAssertFalse(self.sshKey.publicKey.isValidSignature(signature, for: exchangeHash))
    }

    func testRejectsSignatureLabelledWithAnotherAlgorithm() throws {
        let exchangeHash = SHA256.hash(data: Array("exchange".utf8))
        let raw = try self.rsaKey.signature(
            for: SHA256.hash(data: Data(exchangeHash)),
            padding: .insecurePKCS1v1_5
        )

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("rsa-sha2-512".utf8)
        buffer.writeSSHString(raw.rawRepresentation)
        let signature = try XCTUnwrap(buffer.readSSHSignature())

        XCTAssertFalse(self.sshKey.publicKey.isValidSignature(signature, for: exchangeHash))
    }

    func testSHA1SignatureIsNotRead() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHString("ssh-rsa".utf8)
        buffer.writeSSHString(Array(repeating: UInt8(0), count: 256))

        XCTAssertThrowsError(try buffer.readSSHSignature()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .unknownSignature)
        }
    }

    func testRSAKeyIsNotVerifiedByAnotherKindOfSignature() throws {
        let digest = SHA256.hash(data: Array("exchange".utf8))
        let ed25519Signature = try NIOSSHPrivateKey(ed25519Key: .init()).sign(digest: digest)
        let rsaSignature = try self.sshKey.sign(digest: digest)

        XCTAssertFalse(self.sshKey.publicKey.isValidSignature(ed25519Signature, for: digest))
        XCTAssertFalse(NIOSSHPrivateKey(ed25519Key: .init()).publicKey.isValidSignature(rsaSignature, for: digest))
    }

    func testSignatureRoundTrip() throws {
        let digest = SHA256.hash(data: Array("exchange".utf8))
        let signature = try self.sshKey.sign(digest: digest)

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHSignature(signature)
        XCTAssertEqual(try buffer.readSSHSignature(), signature)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    // MARK: - Public keys

    func testPublicKeyRoundTrip() throws {
        let publicKey = self.sshKey.publicKey

        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(publicKey)

        // An RSA key is `ssh-rsa` on the wire whatever algorithm it signs with.
        var prefix = buffer
        XCTAssertEqual(prefix.readSSHStringAsString(), "ssh-rsa")

        XCTAssertEqual(try buffer.readSSHHostKey(), publicKey)
        XCTAssertEqual(buffer.readableBytes, 0)
    }

    func testPublicKeyFromOpenSSHString() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 1024)
        buffer.writeSSHHostKey(self.sshKey.publicKey)
        let encoded = Data(buffer.readableBytesView).base64EncodedString()

        let parsed = try NIOSSHPublicKey(openSSHPublicKey: "ssh-rsa \(encoded) someone@example.com")
        XCTAssertEqual(parsed, self.sshKey.publicKey)
    }

    func testPublicKeySignsUnderTheSHA2AlgorithmsOnly() throws {
        let publicKey = self.sshKey.publicKey

        XCTAssertTrue(publicKey.signs(under: "rsa-sha2-512".utf8))
        XCTAssertTrue(publicKey.signs(under: "rsa-sha2-256".utf8))
        XCTAssertFalse(publicKey.signs(under: "ssh-rsa".utf8))
        XCTAssertFalse(publicKey.signs(under: "ssh-ed25519".utf8))

        let ed25519Key = NIOSSHPrivateKey(ed25519Key: .init()).publicKey
        XCTAssertTrue(ed25519Key.signs(under: "ssh-ed25519".utf8))
        XCTAssertFalse(ed25519Key.signs(under: "rsa-sha2-512".utf8))
    }

    func testCertificateCannotCertifyRSAKey() throws {
        let signingKey = NIOSSHPrivateKey(ed25519Key: .init())
        let signature = try signingKey.sign(digest: SHA256.hash(data: Array("certificate".utf8)))

        XCTAssertThrowsError(
            try NIOSSHCertifiedPublicKey(
                nonce: ByteBufferAllocator().buffer(capacity: 0),
                serial: 1,
                type: .user,
                key: self.sshKey.publicKey,
                keyID: "rsa",
                validPrincipals: [],
                validAfter: 0,
                validBefore: .max,
                criticalOptions: [:],
                extensions: [:],
                signatureKey: signingKey.publicKey,
                signature: signature
            )
        ) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidCertificate)
        }
    }

    // MARK: - User authentication

    private func userAuthRequest(
        algorithm: RSASignatureAlgorithm,
        sessionID: ByteBuffer
    ) throws -> SSHMessage.UserAuthRequestMessage {
        let offer = NIOSSHUserAuthenticationOffer(
            username: "user",
            serviceName: "ssh-connection",
            offer: .privateKey(.init(privateKey: self.sshKey, rsaSignatureAlgorithm: algorithm))
        )
        return try SSHMessage.UserAuthRequestMessage(request: offer, sessionID: sessionID)
    }

    func testUserAuthRequestNamesTheAlgorithmItSignsWith() throws {
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        for algorithm in RSASignatureAlgorithm.allCases {
            let message = try self.userAuthRequest(algorithm: algorithm, sessionID: sessionID)

            var buffer = ByteBufferAllocator().buffer(capacity: 2048)
            buffer.writeSSHMessage(.userAuthRequest(message))
            let bytes = String(decoding: buffer.readableBytesView, as: Unicode.ASCII.self)
            XCTAssertTrue(bytes.contains(algorithm.algorithmName), "\(algorithm)")

            guard case .some(.userAuthRequest(let parsed)) = try buffer.readSSHMessage() else {
                return XCTFail("Expected a user auth request")
            }
            XCTAssertEqual(parsed, message)

            guard case .publicKey(.known(let key, .some(let signature), let parsedAlgorithm)) = parsed.method else {
                return XCTFail("Expected a signed public key request, got \(parsed.method)")
            }
            XCTAssertEqual(parsedAlgorithm, algorithm)
            XCTAssertEqual(signature.rsaSignatureAlgorithm, algorithm)

            for payloadAlgorithm in RSASignatureAlgorithm.allCases {
                let payload = UserAuthSignablePayload(
                    sessionIdentifier: sessionID,
                    userName: "user",
                    serviceName: "ssh-connection",
                    publicKey: key,
                    rsaSignatureAlgorithm: payloadAlgorithm
                )
                XCTAssertEqual(
                    key.isValidSignature(signature, for: payload),
                    payloadAlgorithm == algorithm,
                    "signed with \(algorithm), payload names \(payloadAlgorithm)"
                )
            }
        }
    }

    func testUserAuthRequestWithSignatureOfAnotherAlgorithmIsRejected() throws {
        var sessionID = ByteBufferAllocator().buffer(capacity: 32)
        sessionID.writeBytes(0..<32)

        let signed = try self.userAuthRequest(algorithm: .sha256, sessionID: sessionID)
        guard case .publicKey(.known(let key, .some(let signature), _)) = signed.method else {
            return XCTFail("Expected a signed public key request, got \(signed.method)")
        }

        var mismatched = signed
        mismatched.method = .publicKey(.known(key: key, signature: signature, rsaSignatureAlgorithm: .sha512))

        var buffer = ByteBufferAllocator().buffer(capacity: 2048)
        buffer.writeSSHMessage(.userAuthRequest(mismatched))

        XCTAssertThrowsError(try buffer.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testPublicKeyOKAnswersWithTheAlgorithmOfTheRequest() throws {
        for algorithm in RSASignatureAlgorithm.allCases {
            let message = SSHMessage.UserAuthPKOKMessage(
                key: self.sshKey.publicKey,
                rsaSignatureAlgorithm: algorithm
            )

            var buffer = ByteBufferAllocator().buffer(capacity: 2048)
            buffer.writeSSHMessage(.userAuthPKOK(message))

            guard case .some(.userAuthPKOK(let parsed)) = try buffer.readSSHMessage() else {
                return XCTFail("Expected a public key OK message")
            }
            XCTAssertEqual(parsed, message)
        }
    }

    // MARK: - Key exchange

    private func stateMachines(
        hostKeys: [NIOSSHPrivateKey]
    ) -> (client: SSHKeyExchangeStateMachine, server: SSHKeyExchangeStateMachine) {
        let allocator = ByteBufferAllocator()
        let loop = EmbeddedEventLoop()

        let client = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .client(
                .init(userAuthDelegate: ExplodingAuthDelegate(), serverAuthDelegate: AcceptAllHostKeysDelegate())
            ),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        let server = SSHKeyExchangeStateMachine(
            allocator: allocator,
            loop: loop,
            role: .server(.init(hostKeys: hostKeys, userAuthDelegate: DenyAllServerAuthDelegate())),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        return (client, server)
    }

    /// Runs the key exchange up to the server's reply, which the client has yet to see.
    private func exchangeUpToReply(
        client: inout SSHKeyExchangeStateMachine,
        server: inout SSHKeyExchangeStateMachine
    ) throws -> SSHMessage.KeyExchangeECDHReplyMessage {
        let serverMessage = server.createKeyExchangeMessage()
        let clientMessage = client.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)
        client.send(keyExchange: clientMessage)

        XCTAssertNil(try server.handle(keyExchange: clientMessage))

        guard case .some(.keyExchangeInit(let ecdhInit)) = try client.handle(keyExchange: serverMessage)?.first else {
            throw XCTSkip("The client did not start the exchange")
        }
        client.send(keyExchangeInit: ecdhInit)

        guard case .some(.keyExchangeReply(let reply)) = try server.handle(keyExchangeInit: ecdhInit)?.first else {
            throw XCTSkip("The server did not answer the exchange")
        }
        try server.send(keyExchangeReply: reply)
        return reply
    }

    func testKeyExchangeWithRSAHostKey() throws {
        var (client, server) = self.stateMachines(hostKeys: [self.sshKey])
        let reply = try self.exchangeUpToReply(client: &client, server: &server)

        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, "rsa-sha2-512")
        XCTAssertEqual(reply.hostKey, self.sshKey.publicKey)

        let newKeys = try client.handle(keyExchangeReply: reply).wait()
        guard case .some(.newKeys) = newKeys?.first else {
            return XCTFail("Expected new keys, got \(String(describing: newKeys))")
        }
    }

    func testKeyExchangePrefersAnotherHostKeyOverRSA() throws {
        var (client, server) = self.stateMachines(hostKeys: [self.sshKey, .init(ed25519Key: .init())])
        _ = try self.exchangeUpToReply(client: &client, server: &server)

        XCTAssertEqual(client._testOnly_negotiatedHostKeyAlgorithm, "ssh-ed25519")
    }

    func testKeyExchangeRejectsSignatureOfAnotherAlgorithmThanNegotiated() throws {
        var (client, server) = self.stateMachines(hostKeys: [self.sshKey])
        var reply = try self.exchangeUpToReply(client: &client, server: &server)

        guard case .rsa(let raw, .sha512) = reply.signature.backingSignature else {
            return XCTFail("Expected an rsa-sha2-512 signature, got \(reply.signature)")
        }
        reply.signature = NIOSSHSignature(backingSignature: .rsa(raw, .sha256))

        XCTAssertThrowsError(try client.handle(keyExchangeReply: reply)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
    }

    func testKeyExchangeRejectsRSAKeyWhenAnotherWasNegotiated() throws {
        var (client, server) = self.stateMachines(hostKeys: [.init(ed25519Key: .init())])
        var reply = try self.exchangeUpToReply(client: &client, server: &server)
        reply.hostKey = self.sshKey.publicKey

        XCTAssertThrowsError(try client.handle(keyExchangeReply: reply)) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidHostKeyForKeyExchange)
        }
    }
}
