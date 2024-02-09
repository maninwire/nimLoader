# nimLoader
Loader written in NIM that allows memory execution of Csharp binaries as assemblies, bypassing AMSI and ETW.

This tool is deeply inspired by @s3cur3th1ssh1t and @Byt3bl33d3r work on Nim, and the  [Invoke-Sharploader](https://github.com/S3cur3Th1sSh1t/Invoke-SharpLoader) and [netLoader](https://github.com/Flangvik/NetLoader) tools.

## Use
Basically nimloader allows you to load offensive tools from an url or a file.
Previously you need to create an encrypted file of the tool in question, and then set it in an accesible url or transfer it werever you need it.
Then you use nimloader.exe passing the encrypted key (if you dont want to use the default one) the encrypted file as parameter, then the parameters to the tool itself.

### 1. Preparation phase
Here we encrypt the tool into the txt file that will be loaded.
Nimloader makes use of a few files for the encryption:
- CsharpToNimByteArray.ps1: converts the .NET executable into a a byte array and drops it into a file. This is a slight modification of the tool described at https://s3cur3th1ssh1t.github.io/Playing-with-OffensiveNim
- nimcrypter.exe: encrypter
- autoNim.ps1: Automates the use of the previous two. This is the only file you need to run:
```psh
.\autoNIM.ps1 c:\tools\Rubeus.exe
```

### 2. Attack phase
Here we set the generated encrypted file into an url or we can copy it to destination. Then we run nimloader:

```psh
.\nimLoader.exe -h
    executable.exe [-v] [-d] [-D] [-f] [-k]  <fileOrUrl.txt> [parameters for the file]
    -d: Decrypt file or url
    -D: Debug
    -f: force execution regardless of bypass success
    -k key: key for decryption. Defaults to myverysecretkey
    -v: show version
```
Example:
```psh
.\nimLoader.exe -d .\Rubeus.exeNimByteArray.txt_enc.txt params to rubeus
```

# Video demo
You can see a demo here:
https://youtu.be/AkxCnHMjz7s
