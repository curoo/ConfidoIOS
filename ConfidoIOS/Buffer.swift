//
//  Buffer.swift
//  ConfidoIOS
//
//  Created by Rudolph van Graan on 25/09/2015.
//
//

import Foundation

public typealias Byte = UInt8

public enum BufferError : ErrorType, CustomStringConvertible {
    case WordLengthMismatch

    public var description: String {
        switch self {
        case .WordLengthMismatch: return "WordLengthMismatch"
        }
    }
}


//TODO: Split the struct in two and adopt the protocols below to create a MutableBuffer
public protocol BufferType {
    typealias T
    var values: [T] { get }
//    init()
//    init(size: Int)
//    init(bytes: [T])
//    init(buffer: Self)
//    init(data: NSData) throws
//    init(hexData: String) throws
    var size: Int { get }
    var data: NSData { get }
    var base64String: String  { get }
    var hexString: String { get }
}
/**
public protocol ImmutableBufferType: BufferType {
    var memory: UnsafeBufferPointer<Byte> { get }
}

public protocol MutableBufferType: BufferType {
    var memory: UnsafeMutableBufferPointer<Byte> { get }
    var size: Int { get set }
    mutating func append(bytes: [T])
}
*/

public struct Buffer<T:UnsignedIntegerType> {
    public private(set) var values: [T]
    public var pointer: UnsafeMutablePointer<T> {
        get {
            return UnsafeMutablePointer<T>(values)
        }
    }
    public var mutablePointer: UnsafeMutablePointer<T> {
        get {
            return UnsafeMutablePointer<T>(values)
        }
    }
    public var bufferPointer: UnsafeBufferPointer<Byte> {
        get {
            return UnsafeBufferPointer<Byte>(start: UnsafeMutablePointer(values), count: self.byteCount)
        }
    }
    public var voidPointer: UnsafePointer<Void> {
        get {
            return UnsafePointer<Void>(values)
        }
    }

    public init() {
        values = []
    }
    public init(size: Int) {
        values = [T](count:size, repeatedValue: 0)
    }
    public init(bytes: [T]) {
        self.values = bytes
    }
//TODO:  public init<B where B:BufferType, B.T == T>(buffer: B)
    public init(buffer: Buffer<T>) {
        self.values = buffer.values
    }
    public init(data: NSData) throws {
        let numberOfWords = data.length / sizeof(T)
        if data.length % sizeof(T) != 0 {
            throw BufferError.WordLengthMismatch
        }
        self.init(size: numberOfWords)
        data.getBytes(&values, length:data.length)
    }
    public init(hexData: String) throws {
            let data = NSMutableData()
            var temp = ""
            for char in hexData.characters {
                temp+=String(char)
                if(temp.characters.count == 2) {
                    let scanner = NSScanner(string: temp)
                    var value: UInt32 = 0
                    scanner.scanHexInt(&value)
                    data.appendBytes(&value, length: 1)
                    temp = ""
                }

            }
        try self.init(data: data)
    }
    public var data: NSData {
        get { return NSData(bytes: values, length: byteCount) }
    }
    public var base64String: String {
        get { return data.base64EncodedStringWithOptions([]) }
    }
    public var hexString: String {
        get {
            var hexString = ""
            let pointer = self.bufferPointer
            pointer.forEach { (byte) -> () in
                hexString.appendContentsOf(String(format:"%02x", byte))
            }
            return hexString
        }
    }
    public var size: Int {
        get {
            return values.count
        }
        set {
            if newValue < values.count {
                //truncate the buffer to the new size
                values = Array(values[0..<newValue])
            } else if newValue > values.count {
                let newBuffer = [T](count:newValue, repeatedValue: 0)
                let newBufferPointer = UnsafeMutablePointer<T>(newBuffer)
                newBufferPointer.moveInitializeFrom(self.pointer, count: values.count)
                values = newBuffer
            }
        }
    }
    public var byteCount: Int {
        get {
            return values.count * elementSize
        }
    }

    public mutating func append(bytes: [T])  {
        let currentSize = self.size
        let newSize = self.size + bytes.count
        self.size = newSize
        let appendLocation = self.pointer.advancedBy(currentSize)
        appendLocation.moveAssignFrom(UnsafeMutablePointer(bytes), count: bytes.count)

    }
    public var elementSize: Int {
        get {
            return sizeof(T)
        }
    }
}


extension Array  where Element : UnsignedIntegerType {
    var buffer: Buffer<Element> {
        get { return Buffer(size: 0) }
    }

}