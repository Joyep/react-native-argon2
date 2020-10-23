import Foundation
import SignalArgon2

@objc(RNArgon2)
class RNArgon2: NSObject {

  @objc
  static func requiresMainQueueSetup() -> Bool {
    return true
  }

  @objc
  func argon2(_ params: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock, rejecter reject: @escaping RCTPromiseRejectBlock) -> Void {
    
    let saltData: Data? = Data(base64Encoded: params["salt"] as! String)
    let passwordData: Data? = Data(base64Encoded: params["password"] as! String)
    let typeString: String? = params["type"] as? String
    var type: Argon2.Variant = Argon2.Variant.d
    if typeString == "d" {
        type = Argon2.Variant.d
    } else if typeString == "i" {
        type = Argon2.Variant.i
    } else if typeString == "id" {
        type = Argon2.Variant.id
    }
    
    do {
        let (rawHash, encodedHash) = try Argon2.hash(
            iterations: params["iterations"] as! UInt32,
            memoryInKiB: params["memory"] as! UInt32,
            threads: params["parallelism"] as! UInt32,
            password: passwordData!,
            salt: saltData!,
            desiredLength: params["hashLen"] as! Int,
            variant: type,
            version: .v13
        )

        let resultDictionary: NSDictionary = [
            "rawHash" : rawHash.hexEncodedString(),
            "encodedHash" : encodedHash,
        ]
        resolve(resultDictionary);
    }
    catch {
        let error = NSError(domain: "com.poowf.argon2", code: 200, userInfo: ["Error reason": "Failed to generate argon2 hash"])
        reject("E_ARGON2", "Failed to generate argon2 hash", error)
    }
  }

}

extension Data {
    struct HexEncodingOptions: OptionSet {
        let rawValue: Int
        static let upperCase = HexEncodingOptions(rawValue: 1 << 0)
    }

    func hexEncodedString(options: HexEncodingOptions = []) -> String {
        let hexDigits = Array((options.contains(.upperCase) ? "0123456789ABCDEF" : "0123456789abcdef").utf16)
        var chars: [unichar] = []
        chars.reserveCapacity(2 * count)
        for byte in self {
            chars.append(hexDigits[Int(byte / 16)])
            chars.append(hexDigits[Int(byte % 16)])
        }
        return String(utf16CodeUnits: chars, count: chars.count)
    }
}
