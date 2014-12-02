"use strict";
var exec = require('cordova/exec');

function PinnedHTTPS(expectedFingerprint){
	if (typeof expectedFingerprint != 'string') throw new TypeError('expectedFingerprint must be a string');
	expectedFingerprint = expectedFingerprint.trim().replace(/ +/g, '').toLowerCase();
	//console.log('Expected fingerprint: ' + expectedFingerprint);
	if (!isSHA1(expectedFingerprint)) throw new TypeError('invalid expectedFingerprint. Must be an SHA1 fingerprint');
	this.fingerprint = expectedFingerprint
}

PinnedHTTPS.prototype.get = function(url, callback){
	if (typeof url != 'string') throw new TypeError('url must be a string');
	if (typeof callback != 'function') throw new TypeError('callback must be a function');

	cordova.exec(responseHandler, errorHandler, 'PinnedHTTPS', 'get', [url, this.fingerprint]);

	function responseHandler(responseObj){
		callback(null, JSON.parse(responseObj));
	}
	function errorHandler(errObj){
		callback(errObj);
	}
};

PinnedHTTPS.prototype.request = function(options, callback){
	if (typeof options != 'object') throw new TypeError('options must be an object');
	if (typeof callback != 'function') throw new TypeError('callback must be a function');

	//Checking the mandatory fields of options
	if (typeof options.host != 'string') throw new TypeError('options.host must be a defined string');
	if (typeof options.port == 'number'){
		if (!(options.port > 0 && Math.floor(options.port) == options.port)) throw new TypeError('when defined, port must be a stricly positive integer');
	} else options.port = 443;
	if (options.method){
		if (typeof options.method != 'string') throw new TypeError('when defined, options.method must be a string');
	} else options.method = 'get';
	if (options.headers){
		if (typeof options.headers != 'object') throw new TypeError('when defined, options.headers must be an object');
		var headerKeys = Object.keys(options.headers);
		for (var i = 0; i < headerKeys.length; i++){
			var currentHeaderType = typeof options.headers[headerKeys[i]];
			if (!(currentHeaderType == 'string' || currentHeaderType == 'number' || currentHeaderType == 'boolean')) throw new TypeError('when defined, options.headers must contain either strings, numbers or booleans');
		}
	}

	cordova.exec(responseHandler, errorHandler, 'PinnedHTTPS', 'req', [JSON.stringify(options), this.fingerprint]);

	function responseHandler(responseObj){
		callback(null, JSON.parse(responseObj));
	}
	function errorHandler(errObj){
		callback(errObj);
	}
}

module.exports = PinnedHTTPS;

function isSHA1(s){
	return (typeof s == 'string' && s.length == 40 && /^([a-f]|[0-9])+$/i.test(s));
}
