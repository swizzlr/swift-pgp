//
//  PublicKeyData.swift
//  PGPFormat
//
//  Created by Alex Grinman on 6/3/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a public key data structure
 */
public protocol PublicKeyData {
    init(mpintData:Data) throws
    func toData() -> [UInt8]
}

/**
    The RSA public key data structure
 */
public struct RSAPublicKey:PublicKeyData{
    public let modulus:MPInt
    public let exponent:MPInt
    
    public init(modulus:Data, exponent:Data) {
        self.modulus = MPInt(integerData: modulus)
        self.exponent = MPInt(integerData: exponent)
    }
    
    public init(mpintData: Data) throws {
        let bytes = mpintData.bytes
        
        var start = 0
        
        self.modulus = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count]))
        start += modulus.byteLength
        
        guard bytes.count >= start else {
            throw DataError.tooShort(bytes.count)
        }
        
        self.exponent = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count]))
    }
    
    public func toData() -> [UInt8] {
        var data = Data()
        
        // modulus:  MPI two-octet scalar length then modulus
        data.append(contentsOf: modulus.lengthBytes)
        data.append(modulus.data)
        
        // exponent:  MPI two-octet scalar length then exponent
        data.append(contentsOf: exponent.lengthBytes)
        data.append(exponent.data)
        
        return [UInt8](data)
    }
}

/**
    The Ed25519 and ECDSA public key data structures
    https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00
    https://tools.ietf.org/html/rfc6637#section-9
 */

public struct ECPublicKey: PublicKeyData {
    
    /// The raw curve data, comprising an encoding prefix (compressed/uncompressed) + the encoded curve points
    var rawData: Data
    var curve: Curve
    
    enum ParsingError:Error {
        case missingOrUnsupportedECCPrefixByte
        case badECCCurveOIDLength(UInt8)
        case unsupportedECCCurveOID(Data)
    }
    
    /**
        EC constants:
            - prefix byte (Ed25519 only)
            - curve OID
     */
    public struct Constants {
        public static let ecUncompressedPrefixByte: UInt8 = 0x04
        public static let edEncodedPrefixByte: UInt8 = 0x40
        public static let ed25519OID: [UInt8] = [0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01]
        public static let p256OID: [UInt8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]
    }
    
    public enum Curve {
        case p256
        case ed25519
        var oid: [UInt8] {
            switch self {
            case .p256:
                return Constants.p256OID
            case .ed25519:
                return Constants.ed25519OID
            }
        }
        var encodingPrefixByte: UInt8 {
            switch self {
            case .p256:
                return Constants.ecUncompressedPrefixByte
            case .ed25519:
                return Constants.edEncodedPrefixByte
            }
        }
    }
    
    // The raw bytes of the curve-point, including the prefix byte
    public init(rawData: Data, curveType: Curve) throws {
        guard rawData.first == curveType.encodingPrefixByte else {
            throw ParsingError.missingOrUnsupportedECCPrefixByte
        }
        self.rawData = rawData
        self.curve = curveType
    }
    
    /// initialize with the bytes describing the public key.
    /// In this case, mpintData contains both the initial OID header (length declaration + OID) and the subsequent MPInt of an encoded curve point
    public init(mpintData: Data) throws {
        
        let bytes = mpintData.bytes
        
        guard bytes.count >= 1 + Constants.p256OID.count else { // shortest oid
            throw DataError.tooShort(bytes.count)
        }

        var start = 0
        // FIXME:
        // The first byte indicates OID length.
        // This algorithm works because we only support two curves with OIDs of different lengths.
        // The moment we start supporting more curves, we have to use it as a guide to lookahead, pull out the oid and match against the full oid
        let expectedCurveType: Curve
        switch Int(bytes[start]) {
        case Constants.ed25519OID.count:
            expectedCurveType = .ed25519
        case Constants.p256OID.count:
            expectedCurveType = .p256
        default:
            throw ParsingError.badECCCurveOIDLength(bytes[start])
        }
        
        start += 1
        
        let curveOID = [UInt8](bytes[start ..< start + expectedCurveType.oid.count])
        guard curveOID == expectedCurveType.oid else {
            throw ParsingError.unsupportedECCCurveOID(Data(bytes: curveOID))
        }
        
        start += expectedCurveType.oid.count
        
        guard bytes.count > start else {
            throw DataError.tooShort(bytes.count)
        }
        
        let mpintBytes = try MPInt(mpintData: Data(bytes: bytes[start ..< bytes.count])).data.bytes
    
        guard mpintBytes.first == expectedCurveType.encodingPrefixByte else {
            throw ParsingError.missingOrUnsupportedECCPrefixByte
        }
        
        guard mpintBytes.count > 1 else {
            throw DataError.tooShort(mpintBytes.count)
        }
        self.curve = expectedCurveType
        self.rawData = Data(bytes: mpintBytes)
    }
    
    
    public func toData() -> [UInt8] {
        var data: [UInt8] = []
        let oidLength: UInt8 = UInt8(self.curve.oid.count)
        data.append(contentsOf: [oidLength] + self.curve.oid)
        
        let mpint = MPInt(integerData: Data(bytes: rawData.bytes))
        
        data.append(contentsOf: mpint.lengthBytes)
        data.append(contentsOf: [UInt8](mpint.data))
        
        return data
    }
}
