/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
var https;
var pinnedHTTPSBuilder;
var app = {
    // Application Constructor
    initialize: function() {
        this.bindEvents();
    },
    // Bind Event Listeners
    //
    // Bind any events that are required on startup. Common events are:
    // 'load', 'deviceready', 'offline', and 'online'.
    bindEvents: function() {
        document.addEventListener('deviceready', this.onDeviceReady, false);
    },
    // deviceready Event Handler
    //
    // The scope of 'this' is the event. In order to call the 'receivedEvent'
    // function, we must explicitly call 'app.receivedEvent(...);'
    onDeviceReady: function() {
        pinnedHTTPSBuilder = window.plugins.pinnedhttps;


    },
    onTestBtn: function(){
        var fingerprint = _fingerprint.value;
        https = new pinnedHTTPSBuilder(fingerprint);
        var host = _host.value;
        var path = _path.value;
        var url = 'https://' + host + path;
        https.get(url, function(err, res){
            clearResponse();
            if (err){

            } else {
                appendResponse('Status code: ' + res.statusCode);
                appendResponse('Response headers: ' + JSON.stringify(res.headers));
            }
        }, function(err){

        });
    }
};

function clearResponse(){
    _response.innerHTML = '';
}

function appendResponse(s){
    _response.innerHTML += s + '<br/>';
}
