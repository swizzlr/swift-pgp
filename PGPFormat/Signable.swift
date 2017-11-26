//
//  Signable.swift
//  PGPFormat
//
//  Created by Alex Grinman on 5/21/17.
//  Copyright © 2017 KryptCo, Inc. All rights reserved.
//

import Foundation

/**
    Represents a structure that can be signed
 */
public protocol Signable {
    var signature:Signature { get set }
    func signableData() throws -> Data
}

public extension Signable {    
    public func dataToHash() throws -> Data {
        var dataToHash = try self.signableData()        
        try dataToHash.append(signature.dataToHash())
        
        return dataToHash
    }
    
    public mutating func set(hash:Data, signedHash: [MPInt]) throws {
        try signature.set(hash: hash, signedHash: signedHash)
    }
    
}
