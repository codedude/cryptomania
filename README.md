# Cryptomania - AES implementation

The goal of this project is to implement the AES encryption algorithm with some block mode of operations.


## Usage:
### CLI
```
Command line options:
  -h [ --help ]         produce help message then exit
  -k [ --key ] arg      secret key in hexadecimal
  -n [ --iv ] arg       iv/counter in hexadecimal
  -a [ --aad ] arg      aad for gcm only in hexadecimal
  -l [ --list ]         list supported algorithms then exit
  -e [ --encrypt ]      encrypt input file (default)
  -d [ --decrypt ]      decrypt input file
  -i [ --in ] arg       input file
  -o [ --out ] arg      output file (default = X.[de|en]crypted)
  -m [ --mode ] arg     operation mode (ecb, cbc, ctr)
  -s [ --size ] arg     key size (128, 192, 256)
  -g [ --generate ] arg generate X random bytes in hexadecimal then exit
  --nopad               disable block padding (default is pkcs7). Input size
                        must be a multiple of 16 bytes
  -v [ --verbose ]      verbose mode (default = false)
  -t [ --tag ] arg      authentification tag (for testing purpose only)
```

### Examples
```
cliaes.exe -m gcm -s 256 --nopad -n cafebabefacedbaddecaf888 -k feffe9928665731c6d6a8f9467308308 -a feedfacedeadbeeffeedfacedeadbeefabaddad2 -i plainFile.txt -o encryptedFile.txt
```
