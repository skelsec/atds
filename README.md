# atds
Asynchronous TDS Client for MSSQL

# Current status
Do not use this library in production, it is not stable and the API WILL CHANGE.  

This library is quite basic, supports plaintext, Kerberos and NTLM authentication, and can execute queries.  
Thanks to the awesome [pytds](https://github.com/denisenkom/pytds) library, most column and row parsing is implemented correctly.  


# TODO
- [ ] Add support for MARS
- [ ] Add support for SMP
- [ ] Add support for versions >7.1
- [ ] Implement session management
- [ ] Implement cursors