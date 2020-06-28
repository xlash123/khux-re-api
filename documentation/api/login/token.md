# Token
`GET` a login token, cookie, and url to get session from

## Parameters
Method: `GET`

SearchParams:
+ m=0


## Response
Set-Cookie:
+ nodeNo=#
+ (session_cookie)
	+ Expires in 24 hours

Body:
+ nativeToken
	+ A token forwarded to the provided URL to obtain a session
+ url
	+ The URL from which to obtain a session