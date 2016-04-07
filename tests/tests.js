exports.defineAutoTests = function(){

	var https;

	describe('cordova-plugin-pinnedhttps', function(){

		it('should be defined', function(){
			expect(window.navigator.httpsBuilder).toBeDefined();
		});

		var hosts = {
			'lockate.me': [
				'12 C4 48 23 85 8C 3E 19 D1 FF 42 C2 E6 BE 81 17 F9 11 0B 2E',
				'24 71 06 A4 05 B2 88 A4 6E 70 A0 26 27 17 16 2D 09 03 E7 34'
			],
			'srv.lockate.me': [
				'AC 53 AB 21 38 6E 51 CD 61 0E 56 E1 D9 8A E1 12 3A C2 58 BF'
			]

			/*
			*	Doesn't really work with these hosts.
			*	Reasons :
			*		multiple certificates server (for Facebook);
			*		cross-signed certificates (for OSM)
			*/
			/*'a.tile.openstreetmap.org': [
				'C3 EB A1 A5 86 3E 07 3C 0A 40 17 FE D9 4E 61 BC 0A 32 A3 20',
				'0E 34 14 18 46 E7 42 3D 37 F2 0D C0 AB 06 C9 BB D8 43 DC 24',
				'DE 28 F4 A4 FF E5 B9 2F A3 C5 03 D1 A3 49 A7 F9 96 2A 82 12'
			],
			'www.facebook.com': [
				'A0 4E AF B3 48 C2 6B 15 A8 C1 AA 87 A3 33 CA A3 CD EE C9 C9',
				'A0 31 C4 67 82 E6 E6 C6 62 C2 C8 7C 76 DA 9A A6 2C CA BD 8E',
				'5F B7 EE 06 33 E2 59 DB AD 0C 4C 9A E6 D3 8F 1A 61 C7 DC 25'
			]*/
		}

		var hostsList = Object.keys(hosts);

		hostsList.forEach(function(hostname){
			var hostFingerprints = hosts[hostname];
			hostFingerprints.forEach(function(f){
				testHost(hostname, f);
			});
		});

		function testHost(h, f){
			it('should initialize the Pinned HTTPS client', function(){
				https = new window.navigator.httpsBuilder(f);

				expect(https).toBeDefined();;
			});

			it('tests against https://' + h, function(done){
				https.get('https://' + h, function(err, res){
					expect(!!err).toBe(false);
					if (err){
						console.error(JSON.stringify(err));
						done();
						return;
					}

					console.log('Status code on ' + h + ': ' + res.statusCode);

					done();
				});
			});
		}

	});

}
