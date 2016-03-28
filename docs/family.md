Family configuration
====================

Your might want to specify a family, your router belongs to.
There are two possibilities: create new family or joing to existing.

New family
-----------

You must create family self-signed certificate and key.  
The only key type supposted is prime256v1.
Use the following list of commands:  

    openssl ecparam -name prime256v1 -genkey -out <your family name>.key  
    openssl req -new -key <your family name>.key -out <your family name>.csr  
    touch v3.ext
    openssl x509 -req -days 3650 -in <your family name>.csr -signkey <your family name>.key -out <your family name>.crt -extfile v3.ext  

Specify <your family name>.family.i2p.net for CN (Common Name) when requested.

Once you are done with it place <your-family-name>.key and <your-family-name>.crt to <ip2d data>/family folder (for exmple ~/.i2pd/family).
You should provide these two files to other members joining your family.
If you want to register you family and let I2P network recorgnize it, create pull request for you .crt file into contrib/certificate/family.
It will appear in i2pd and I2P next releases packages. Dont place .key file, it must be shared between you family members only.

How to join existing family
---------------------------

Once you and that family agree to do it, they must give you .key and .crt file and you must place in <i2pd datadir>/certificates/family/ folder.

Publish your family
-------------------

Run i2pd with parameter 'family=<your-family-name>', make sure you have <your-family-name>.key and <your-family-name>.crt in your 'family' folder.
If everything is set properly, you router.info will contain two new fields: 'family' and 'family.sig'.
Otherwise your router will complain on startup with log messages starting with "Family:" prefix and severity 'warn' or 'error'.
