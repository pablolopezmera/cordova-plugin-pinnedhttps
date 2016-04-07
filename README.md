# cordova-plugin-pinnedhttps


A phonegap plugin that will allow you to make HTTPS requests with certificate fingerprint verification


## Installation


```
phonegap plugin add cordova-plugin-pinnedhttps
```

## Usage

This plugin compiles and has been tested as part of an other project (a cordova app).

__NOTE:__ This plugin doesn't follow HTTP redirections

```js
/*
The `fingerprints` parameter must either be a string or an array of
strings; each string must be an SHA1 or SHA256 hash. (SHA1 and SHA256 cannot
be mixed)

Note that some sites use multiple certificates (on the same hostname), and some others use cross-signed certificates. These cases might trigger "INVALID_CERT" errors
 */
var https = new navigator.httpsBuilder(fingerprints);

https.get('https://yoursite.tld/yourpath', function(err, res){
	if (err){
		//Handle errors here. err is a string
		if (err == 'INVALID_CERT'){
			//Certificate found on server doesn't match the provided fingerprint
		} else {
			//Other kinds of connection errors. Error messages are listed below
		}
	} else {
		res.statusCode //Number
		res.headers //Object
		res.body //String
	}
});

var reqOptions = {method:'post', host:'yoursite.tld', path: '/yourpath', [port: 443], [headers: {header1: 'value1', header2: 'value2'}], [body: {}]};

https.request(reqOptions, function(err, res){
	if (err){
		//Handle errors here. err is a string
		if (err == 'INVALID_CERT'){
			//Certificate found on server doesn't match the provided fingerprint
		} else {
			//Other kinds of connection errors. Error messages are listed below
		}
	} else {
		res.statusCode //Number
		res.headers //Object
		res.body //String
	}
});
```
__NOTE__ : With `https.request`, if `returnBuffer` is defined in the `reqOptions`, then `res.body` will be returned as an `Uint8Array`


## List of error messages


Error message	| Meaning
----------------|------------------------------------
`INVALID_PARAMS`| Invalid parameters
`INVALID_URL`	| Invalid URL
`INVALID_METHOD`| Invalid HTTP method
`INVALID_HEADERS`| Invalid `options.headers` parameter
`INVALID_BODY`	| Invalid `options.body` parameter
`INVALID_CERT`	| Invalid certificate found on server
`CANT_CONNECT`	| Can't connect to the server
`TIMEOUT`		| Connection timeout
`INTERNAL_ERROR`| Internal error
