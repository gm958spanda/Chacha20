Chacha20加密算法

从 openssl中移植


*
* Copyright 2015-2018 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*


example:

```java
        String str = "hello world";

        int key[] = {-123,-456,789,123,456,7890,456,456};
        int noc[] = {-123,-456,789,123};

        byte[] encryptData = Chacha20.crytpoCounter32(str.getBytes(),key,noc);

        byte[] decryptData = Chacha20.crytpoCounter32(encryptData,key,noc);
        
        String str2 = new String(decryptData);
        
        boolean equal = str.equals(str2);
```
