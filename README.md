# X_509_Demo
Self signed X_509 certificate using C++ and OpenSSL library
# How to run this program
+ Add OpenSSL library link in project
``` LINK OPENSSL-3.0.1 LIBRARY TO SOURCE CODE IN VISUAL STUDIO 2022
  IN PROPERTIES OF PROJECT, C++ -> CHOOSE EDIT PATH -> PASTE LINK TO ..\OpenSLL-3.0.1\SHARED\x64\Debug\include

  IN LINK -> CHOOSE INPUT -> EDIT ENVIROMENT -> PASTE 2 LINK ..\OpenSLL-3.0.1\SHARED\x64\Debug\lib\libcrypto.lib
  ..\OpenSLL-3.0.1\SHARED\x64\Debug\lib\libssl.lib
```
# Command to know content of cer.pem and key.pem
```
openssl rsa -text -noout -in key.pem

openssl x509 -text -noout -in cer.pem
```
# Link video demo
https://youtu.be/jJutZ5BQJrU  
![image](https://github.com/TranThiKimHuynh/X_509_Demo/assets/95559644/4c1345b4-a499-427e-8b88-955b777c1099)
