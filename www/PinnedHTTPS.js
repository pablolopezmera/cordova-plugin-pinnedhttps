"use strict";
var exec = require('cordova/exec');

function PinnedHTTPS(expectedFingerprint){
}

PinnedHTTPS.prototype.get = function(url, callback){
	if (typeof url != 'string') throw new TypeError('url must be a string');
	if (typeof callback != 'function') throw new TypeError('callback must be a function');

	cordova.exec(responseHandler, errorHandler, 'get', [url, expectedFingerprint]);

	function responseHandler(responseObj){
		callback(null, responseObj);
	}
	function errorHandler(errObj){
		callback(errObj);
	}
};

PinnedHTTPS.prototype.request = function(options, callback){
	if (typeof options != 'object') throw new TypeError('options must be an object');
	if (typeof callback != 'function') throw new TypeError('callback must be a function');

	
}

module.exports.PinnedHTTPS = PinnedHTTPS;
