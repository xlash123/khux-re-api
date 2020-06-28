# Login
Using the cookie obtained from /token, and the body encrypted with the `sharedSecurityKey`, log into the server.

## Parameters
Method: `POST`

Cookie:
+ nAJW839RbEHrfm6M
	+ The session cookie
+ x-sqex-hole-nsid
	+ The `nativeSessionId` obtained from the session endpoint
+ x-sqex-hole-retry
	+ Likely the login retry count
+ content-length

Body:
+ length
	+ No idea, but it's the same for every login attempt
+ digest
	+ No idea, but it's the same for every login attempt
+ ruv
+ deviceType
+ systemVersion
+ appVersion


## Response
Set-Cookie:
+ nodeNo=#
+ cookie_user_session_code
	+ The user session code. Expires in 24 hours
+ nAJW839RbEHrfm6M
	+ A new session token (different from the one sent). Expires in 24 hours

Body:
+ ret
+ systemLogin
	+ An object showing whether the user is new to either game
+ data
	+ An array of something base64 encoded. Looks to be the same every time
+ (a bunch of links)