# PinnedHTTPS-Phonegap-Plugin


A phonegap plugin that will allow you to make HTTPS requests with certificate fingerprint verification


## Installation


```
phonegap plugin add https://github.com/BatikhSouri/PinnedHTTPS-Phonegap-Plugin
```

## API

**Currently, this plugin compiles but hasn't been tested**

### Usage

```js
var https = new navigator.httpsBuilder(fingerprintStr);

https.get('https://yoursite.tld/yourpath', function(err, res){
	if (err){
		//Handle errors here
	} else {
		res.statusCode
		res.headers
		res.body
	}
});

var reqOptions = {method:'post', host:'yoursite.tld', path: '/yourpath', [port: 443], [headers: {header1: 'value1', header2: 'value2'}]};

https.request(reqOptions, function(err, res){
	if (err){
		//Handle errors here
	} else {
		res.statusCode
		res.headers
		res.body
	}
});
```
