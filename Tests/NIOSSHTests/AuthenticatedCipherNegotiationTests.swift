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
import XCTest

@testable import NIOSSH

final class AuthenticatedCipherNegotiationTests: XCTestCase {
    private func stateMachines() -> (client: SSHKeyExchangeStateMachine, server: SSHKeyExchangeStateMachine) {
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
            role: .server(
                .init(hostKeys: [.init(ed25519Key: .init())], userAuthDelegate: DenyAllServerAuthDelegate())
            ),
            remoteVersion: Constants.version,
            protectionSchemes: [AES256GCMOpenSSHTransportProtection.self],
            previousSessionIdentifier: nil
        )
        return (client, server)
    }

    func testCipherWithItsOwnAuthenticationNeedsNoCommonMAC() throws {
        var (client, server) = self.stateMachines()

        var serverMessage = server.createKeyExchangeMessage()
        serverMessage.macAlgorithmsClientToServer = ["hmac-sha2-512-etm@openssh.com"]
        serverMessage.macAlgorithmsServerToClient = ["hmac-sha2-512-etm@openssh.com"]
        let clientMessage = client.createKeyExchangeMessage()
        client.send(keyExchange: clientMessage)

        guard case .some(.keyExchangeInit) = try client.handle(keyExchange: serverMessage)?.first else {
            return XCTFail("The client did not start the exchange")
        }
    }

    func testServerNegotiatesWithClientThatOffersNoCommonMAC() throws {
        var (client, server) = self.stateMachines()

        var clientMessage = client.createKeyExchangeMessage()
        clientMessage.macAlgorithmsClientToServer = ["hmac-sha2-512-etm@openssh.com"]
        clientMessage.macAlgorithmsServerToClient = ["hmac-sha2-512-etm@openssh.com"]
        let serverMessage = server.createKeyExchangeMessage()
        server.send(keyExchange: serverMessage)

        XCTAssertNil(try server.handle(keyExchange: clientMessage))
    }
}
