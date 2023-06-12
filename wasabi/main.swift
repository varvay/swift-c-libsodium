//
//  main.swift
//  wasabi
//
//  Created by Varid Vaya Yusuf on 12/06/23.
//

import Foundation

//  Generate Client Signing Key Pair

var clientPublicKey = Data(count: Int(crypto_sign_PUBLICKEYBYTES))
var clientSecretKey = Data(count: Int(crypto_sign_SECRETKEYBYTES))

_ = clientPublicKey.withUnsafeMutableBytes { clientPublicKeyPtr in
    clientSecretKey.withUnsafeMutableBytes { clientSecretKeyPtr in
        crypto_sign_keypair(clientPublicKeyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                            clientSecretKeyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self))
    }
}

print("Client Public Signing Key: \(data2Hex(clientPublicKey))")
print("Client Private Signing Key: \(data2Hex(clientSecretKey))")

//  Encrypt
let message = "Hello, Wasabi!".data(using: .utf8)!
var nonce = Data(count: Int(crypto_aead_aes256gcm_NPUBBYTES))
let key = hexStringToData("657b2626cab1b88ae9c2e5c04eb1dfc7dbeb475cd50d96006e10ae2fba4e0646")
var ciphertext = Data(count: message.count + Int(crypto_aead_aes256gcm_ABYTES))

_ = nonce.withUnsafeMutableBytes { noncePtr in
    randombytes_buf(noncePtr, Int(crypto_aead_aes256gcm_NPUBBYTES))
}

_ = message.withUnsafeBytes { messagePtr in
    ciphertext.withUnsafeMutableBytes { ciphertextPtr in
        nonce.withUnsafeBytes { noncePtr in
            key.withUnsafeBytes { keyPtr in
                crypto_aead_aes256gcm_encrypt(ciphertextPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                              nil,
                                              messagePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                              UInt64(message.count),
                                              nil,
                                              0,
                                              nil,
                                              noncePtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                              keyPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
                )
            }
        }
    }
}

print("Client Enc Key: \(data2Hex(key))")
print("Client Enc Nonce: \(data2Hex(nonce))")
print("Client Enc Ciphertext: \(data2Hex(ciphertext))")

func data2Hex(_ data: Data) -> String {
    return data.map { String(format: "%02hhx", $0) }.joined()
}

func hexStringToData(_ hexString: String) -> Data {
    let hexChars = Array(hexString)
    let byteCount = hexChars.count / 2
    var byteArray = [UInt8](repeating: 0, count: byteCount)

    for i in 0..<byteCount {
        let startIndex = hexString.index(hexString.startIndex, offsetBy: i * 2)
        let endIndex = hexString.index(startIndex, offsetBy: 2)
        let hexByte = String(hexString[startIndex..<endIndex])

        if let byte = UInt8(hexByte, radix: 16) {
            byteArray[i] = byte
        } else {
            fatalError("Invalid hexadecimal string")
        }
    }
    
    return Data(byteArray)
}
