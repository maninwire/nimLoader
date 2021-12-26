import nimcrypto
import nimcrypto/sysrand
import base64
import os   
import strformat
import strutils
import std/parseopt # option parser


const iv: array[aes256.sizeBlock, byte]= [byte 55, 19, 19, 173, 190, 70, 130, 254, 26, 241, 14, 4, 213, 94, 108, 237]
const envkey: string = "myverysecretkey"

func toByteSeq*(str: string): seq[byte] {.inline.} =
    # Converts a string to the corresponding byte sequence
    @(str.toOpenArrayByte(0, str.high))

when isMainModule:
    var inFile: string =""
    var operation: string = ""
    var passkeystr:string=envkey# default key to our constant
    var helpMsg: string="nimEncrypter.exe [-d|-e] [-k] file.txt" # help msg
    var debug: bool=false # to enable/disable debug mode


    # OUR OPTION PARSER
    var parser = initOptParser() 
    while true:
      parser.next()
      case parser.kind
      of cmdEnd: 
        break
      of cmdShortOption, cmdLongOption:
        if parser.val == "": #just options "-x"
          if parser.key=="d": # decrypt option
            operation="decrypt"
          if parser.key=="e": # encrypt option
            operation="encrypt"
          elif parser.key=="D": # debug option
            debug=true
          elif parser.key=="h": # help option
            echo helpMsg
            quit(QuitSuccess)

        else: # have value

          if parser.key=="k": # key option
            passkeystr=parser.val

      of cmdArgument:
        inFile=parser.key # argument input file

    if inFile=="" or operation=="":
      quit()



    
    let inFileContents: string = readFile(inFile)
    var 

        data: seq[byte] = toByteSeq(inFileContents)
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte]
        plaintext = newSeq[byte](len(data))
        transformedText = newSeq[byte](len(data))


    copyMem(addr plaintext[0], addr data[0], len(data))
    # Expand key to 32 bytes using SHA256 as the KDF
    var expandedkey = sha256.digest(passkeystr)
    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data))


    ectx.init(key, iv)
    if operation=="encrypt":
        ectx.encrypt(plaintext, transformedText)
        writeFile(inFile&"_enc.txt", transformedText)

    elif operation=="decrypt":
        ectx.decrypt(plaintext, transformedText)
        writeFile(inFile&"_dec.txt", transformedText)     
    else:
        ectx.clear()
        system.quit()


        
