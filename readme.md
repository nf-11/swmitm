## README
Note that this proxy is more intrusive than SWEX, as it modifies the login request and changes server responses' encryption.<br>
Modified login request looks exactly the same as if it was sent from the game client, and there is no checksum in the login request,
so server cannot differentiate between modified and non-modified request.<br>
Client also can't detect that the response is modified, since it does not know which responses should be encrypted with the new algorithm.
# Warning
This proxy is (probably) safe to use with the 8.2.4 version of the game, but this may change after any update, so it's best not to use it with your main account.
