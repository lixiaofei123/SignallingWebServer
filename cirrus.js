// Copyright Epic Games, Inc. All Rights Reserved.

//-- Server side logic. Serves pixel streaming WebRTC-based page, proxies data back to Streamer --//

var express = require('express');
var cors = require('cors');
var app = express();

const fs = require('fs');
const path = require('path');
const querystring = require('querystring');
const bodyParser = require('body-parser');
const logging = require('./modules/logging.js');
logging.RegisterConsoleLogger();

// Command line argument --configFile needs to be checked before loading the config, all other command line arguments are dealt with through the config object

const defaultConfig = {
	UseFrontend: false,
	UseHTTPS: false,
	UseAuthentication: false,
	LogToFile: true,
	HomepageFile: 'player.html',
	AdditionalRoutes: new Map(),
	EnableWebserver: true
};

const argv = require('yargs').argv;
var configFile = (typeof argv.configFile != 'undefined') ? argv.configFile.toString() : path.join(__dirname, 'config.json');
console.log(`configFile ${configFile}`);
const config = require('./modules/config.js').init(configFile, defaultConfig);

if (config.LogToFile) {
	logging.RegisterFileLogger('./logs');
}

console.log("Config: " + JSON.stringify(config, null, '\t'));

var http = require('http').Server(app);

if (config.UseHTTPS) {
	//HTTPS certificate details
	const options = {
		key: fs.readFileSync(path.join(__dirname, './certificates/sany.lixf.ink_nginx/sany.lixf.ink.key')),
		cert: fs.readFileSync(path.join(__dirname, './certificates/sany.lixf.ink_nginx/sany.lixf.ink_bundle.crt'))
	};

	var https = require('https').Server(options, app);
}

//If not using authetication then just move on to the next function/middleware
var isAuthenticated = redirectUrl => function (req, res, next) { return next(); }

if (config.UseAuthentication && config.UseHTTPS) {
	var passport = require('passport');
	require('./modules/authentication').init(app);
	// Replace the isAuthenticated with the one setup on passport module
	isAuthenticated = passport.authenticationMiddleware ? passport.authenticationMiddleware : isAuthenticated
} else if (config.UseAuthentication && !config.UseHTTPS) {
	console.error('Trying to use authentication without using HTTPS, this is not allowed and so authentication will NOT be turned on, please turn on HTTPS to turn on authentication');
}

const helmet = require('helmet');
var hsts = require('hsts');
var net = require('net');

var FRONTEND_WEBSERVER = 'https://localhost';
if (config.UseFrontend) {
	var httpPort = 3000;
	var httpsPort = 8000;

	//Required for self signed certs otherwise just get an error back when sending request to frontend see https://stackoverflow.com/a/35633993
	process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"

	const httpsClient = require('./modules/httpsClient.js');
	var webRequest = new httpsClient();
} else {
	var httpPort = config.HttpPort;
	var httpsPort = config.HttpsPort;
}

var streamerPort = config.StreamerPort; // port to listen to Streamer connections

var gameSessionId;
var userSessionId;
var serverPublicIp;

// `clientConfig` is send to Streamer and Players
// Example of STUN server setting
// let clientConfig = {peerConnectionOptions: { 'iceServers': [{'urls': ['stun:34.250.222.95:19302']}] }};
var clientConfig = { type: 'config', peerConnectionOptions: {} };

// Parse public server address from command line
// --publicIp <public address>
try {
	if (typeof config.PublicIp != 'undefined') {
		serverPublicIp = config.PublicIp.toString();
	}

	if (typeof config.HttpPort != 'undefined') {
		httpPort = config.HttpPort;
	}

	if (typeof config.HttpsPort != 'undefined') {
		httpsPort = config.HttpsPort;
	}

	if (typeof config.StreamerPort != 'undefined') {
		streamerPort = config.StreamerPort;
	}

	if (typeof config.FrontendUrl != 'undefined') {
		FRONTEND_WEBSERVER = config.FrontendUrl;
	}

	if (typeof config.peerConnectionOptions != 'undefined') {
		clientConfig.peerConnectionOptions = JSON.parse(config.peerConnectionOptions);
		console.log(`peerConnectionOptions = ${JSON.stringify(clientConfig.peerConnectionOptions)}`);
	} else {
		console.log("No peerConnectionConfig")
	}

} catch (e) {
	console.error(e);
	process.exit(2);
}

if (config.UseHTTPS) {
	app.use(helmet());

	app.use(hsts({
		maxAge: 15552000  // 180 days in seconds
	}));

	//Setup http -> https redirect
	console.log('Redirecting http->https');
	app.use(function (req, res, next) {
		if (!req.secure) {
			if (req.get('Host')) {
				var hostAddressParts = req.get('Host').split(':');
				var hostAddress = hostAddressParts[0];
				if (httpsPort != 443) {
					hostAddress = `${hostAddress}:${httpsPort}`;
				}
				return res.redirect(['https://', hostAddress, req.originalUrl].join(''));
			} else {
				console.error(`unable to get host name from header. Requestor ${req.ip}, url path: '${req.originalUrl}', available headers ${JSON.stringify(req.headers)}`);
				return res.status(400).send('Bad Request');
			}
		}
		next();
	});
}

sendGameSessionData();

//Setup the login page if we are using authentication
if (config.UseAuthentication) {
	if (config.EnableWebserver) {
		app.get('/login', function (req, res) {
			res.sendFile(__dirname + '/login.htm');
		});
	}

	// create application/x-www-form-urlencoded parser
	var urlencodedParser = bodyParser.urlencoded({ extended: false })

	//login page form data is posted here
	app.post('/login',
		urlencodedParser,
		passport.authenticate('local', { failureRedirect: '/login' }),
		function (req, res) {
			//On success try to redirect to the page that they originally tired to get to, default to '/' if no redirect was found
			var redirectTo = req.session.redirectTo ? req.session.redirectTo : '/';
			delete req.session.redirectTo;
			console.log(`Redirecting to: '${redirectTo}'`);
			res.redirect(redirectTo);
		}
	);
}

if (config.EnableWebserver) {
	//Setup folders
	app.use(express.static(path.join(__dirname, '/public')))
	app.use('/images', express.static(path.join(__dirname, './images')))
	app.use('/scripts', [isAuthenticated('/login'), express.static(path.join(__dirname, '/scripts'))]);
	app.use('/', [isAuthenticated('/login'), express.static(path.join(__dirname, '/custom_html'))])
}

app.options('/status', cors())
app.get('/status', cors(), (req, res) => {
	let clone = new Map(streamers);
	let freenum = 0;
	let ips = []
	for (let streamer0 of clone.values()) {
		if (streamer0.status === 'free') {
			freenum++;
		} else {
			ips.push(streamer0.ip)
		}
	}

	res.json({
		count: clone.size,
		freenum: freenum,
		ips: ips
	});
});


try {
	for (var property in config.AdditionalRoutes) {
		if (config.AdditionalRoutes.hasOwnProperty(property)) {
			console.log(`Adding additional routes "${property}" -> "${config.AdditionalRoutes[property]}"`)
			app.use(property, [isAuthenticated('/login'), express.static(path.join(__dirname, config.AdditionalRoutes[property]))]);
		}
	}
} catch (err) {
	console.error(`reading config.AdditionalRoutes: ${err}`)
}

if (config.EnableWebserver) {
	app.get('/', isAuthenticated('/login'), function (req, res) {
		homepageFile = (typeof config.HomepageFile != 'undefined' && config.HomepageFile != '') ? config.HomepageFile.toString() : defaultConfig.HomepageFile;
		homepageFilePath = path.join(__dirname, homepageFile)

		fs.access(homepageFilePath, (err) => {
			if (err) {
				console.error('Unable to locate file ' + homepageFilePath)
				res.status(404).send('Unable to locate file ' + homepageFile);
			}
			else {
				res.sendFile(homepageFilePath);
			}
		});
	});
}

//Setup http and https servers
http.listen(httpPort, function () {
	console.logColor(logging.Green, 'Http listening on *: ' + httpPort);
});

if (config.UseHTTPS) {
	https.listen(httpsPort, function () {
		console.logColor(logging.Green, 'Https listening on *: ' + httpsPort);
	});
}

console.logColor(logging.Cyan, `Running Cirrus - The Pixel Streaming reference implementation signalling server for Unreal Engine 4.27.`);

let WebSocket = require('ws');
let streamerServer = new WebSocket.Server({ port: streamerPort, backlog: 1 });
console.logColor(logging.Green, `WebSocket listening to Streamer connections on :${streamerPort}`)

let streamers = new Map(); // WebSocket connected to Streamer

let getUniqueID = function () {
	function s4() {
		return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
	}
	return s4() + '-' + s4() + '-' + s4() + '-' + s4();
};

streamerServer.on('connection', function (ws, req) {

	let reqId = getUniqueID()

	console.logColor(logging.Green, `Streamer ${reqId} connected: ${req.connection.remoteAddress}`);

	ws.on('message', function onStreamerMessage(msg) {
		console.logColor(logging.Blue, `<- Streamer  ${reqId}: ${msg}`);

		try {
			msg = JSON.parse(msg);
		} catch (err) {
			console.error(`cannot parse Streamer  ${reqId} message: ${msg}\nError: ${err}`);
			ws.close(1008, 'Cannot parse');
			return;
		}

		try {
			if (msg.type == 'ping') {
				ws.send(JSON.stringify({ type: "pong", time: msg.time }));
				return;
			}

			let playerId = msg.playerId;
			delete msg.playerId; // no need to send it to the player

			// Convert incoming playerId to a string if it is an integer, if needed. (We support receiving it as an int or string).
			if (playerId && typeof playerId === 'number') {
				playerId = playerId.toString();
			}

			let player = players.get(playerId);
			if (!player) {
				console.log(`dropped message ${msg.type} as the player ${playerId} is not found`);
				return;
			}

			if (msg.type == 'answer') {
				player.ws.send(JSON.stringify(msg));
			} else if (msg.type == 'iceCandidate') {
				player.ws.send(JSON.stringify(msg));
			} else if (msg.type == 'disconnectPlayer') {

				player.ws.close(1011 /* internal error */, msg.reason);


			} else {
				console.error(`unsupported Streamer message type: ${msg.type}`);
				ws.close(1008, 'Unsupported message type');
			}
		} catch (err) {
			console.error(`ERROR: ws.on message error: ${err.message}`);
		}
	});

	function onStreamerDisconnected() {
		streamers.delete(reqId)
		disconnectAllPlayers(reqId);

	}

	ws.on('close', function (code, reason) {
		try {
			console.error(`streamer  ${reqId} disconnected: ${code} - ${reason}`);
			onStreamerDisconnected();
		} catch (err) {
			console.error(`ERROR: ws.on close error: ${err.message}`);
		}
	});

	ws.on('error', function (error) {
		try {
			console.error(`streamer  ${reqId} connection error: ${error}`);
			ws.close(1006 /* abnormal closure */, error);
			onStreamerDisconnected();
		} catch (err) {
			console.error(`ERROR: ws.on error: ${err.message}`);
		}
	});

	streamers.set(reqId, {
		ws: ws,
		reqId: reqId,
		status: 'free'
	})

	ws.send(JSON.stringify(clientConfig));
});

let playerServer = new WebSocket.Server({ server: config.UseHTTPS ? https : http });
console.logColor(logging.Green, `WebSocket listening to Players connections on :${httpPort}`)

let players = new Map(); // playerId <-> player, where player is either a web-browser or a native webrtc player
let nextPlayerId = 100;

function heartbeat() {
	this.isAlive = true;
}


playerServer.on('connection', function (ws, req) {

	let streamerObj = undefined;

	// 检查有没有空闲的实例
	let clone = new Map(streamers);
	for (let streamer0 of clone.values()) {
		if (streamer0.status === 'free') {
			streamerObj = streamer0
			streamer0.status = 'busy'
			streamer0.ip = req.connection.remoteAddress
			streamers.set(streamer0.reqId, streamer0)
			break
		}
	}

	if (!streamerObj || streamerObj.ws.readyState != 1) {
		ws.close(1013 /* Try again later */, 'Streamer is not connected');
		return;
	}

	ws.isAlive = true;
	ws.on('pong', heartbeat);

	let streamer = streamerObj.ws
	let reqId = streamerObj.reqId

	let playerId = (++nextPlayerId).toString();
	console.log(`player ${playerId} (${req.connection.remoteAddress}) connected`);
	players.set(playerId, { ws: ws, id: playerId, reqId: reqId });

	function sendPlayersCount() {
		let playerCountMsg = JSON.stringify({ type: 'playerCount', count: players.size });
		for (let p of players.values()) {
			p.ws.send(playerCountMsg);
		}
	}

	ws.on('message', function (msg) {
		console.logColor(logging.Blue, `<- player ${playerId}: ${msg}`);

		try {
			msg = JSON.parse(msg);
		} catch (err) {
			console.error(`Cannot parse player ${playerId} message: ${err}`);
			ws.close(1008, 'Cannot parse');
			return;
		}

		if (msg.type == 'offer') {
			console.log(`<- player ${playerId}: offer`);
			msg.playerId = playerId;
			streamer.send(JSON.stringify(msg));
		} else if (msg.type == 'iceCandidate') {
			console.log(`<- player ${playerId}: iceCandidate`);
			msg.playerId = playerId;
			streamer.send(JSON.stringify(msg));
		} else if (msg.type == 'stats') {
			console.log(`<- player ${playerId}: stats\n${msg.data}`);
		} else if (msg.type == 'kick') {
			let playersCopy = new Map(players);
			for (let p of playersCopy.values()) {
				if (p.id != playerId) {
					console.log(`kicking player ${p.id}`)
					p.ws.close(4000, 'kicked');
				}
			}
		} else {
			console.error(`<- player ${playerId}: unsupported message type: ${msg.type}`);
			ws.close(1008, 'Unsupported message type');
			return;
		}
	});

	function onPlayerDisconnected() {
		try {
			players.delete(playerId);

			let streamerObj = streamers.get(reqId)
			if (streamerObj) {
				streamerObj.status = 'free'
				streamers.set(reqId, streamerObj)
			}


			streamer.send(JSON.stringify({ type: 'playerDisconnected', playerId: playerId }));
			sendPlayerDisconnectedToFrontend();
			sendPlayersCount();

		} catch (err) {
			console.logColor(loggin.Red, `ERROR:: onPlayerDisconnected error: ${err.message}`);
		}
	}

	ws.on('close', function (code, reason) {
		console.logColor(logging.Yellow, `player ${playerId} connection closed: ${code} - ${reason}`);
		onPlayerDisconnected();
	});

	ws.on('error', function (error) {
		console.error(`player ${playerId} connection error: ${error}`);
		ws.close(1006 /* abnormal closure */, error);
		onPlayerDisconnected();

		console.logColor(logging.Red, `Trying to reconnect...`);
		reconnect();
	});

	sendPlayerConnectedToFrontend();

	ws.send(JSON.stringify(clientConfig));

	sendPlayersCount();
});

// 检查异常断掉的连接
const interval = setInterval(function ping() {
	playerServer.clients.forEach(function each(ws) {
		if (ws.isAlive === false){ 
			console.logColor(logging.Green, `检查到客户端异常退出.....`)
			return ws.terminate()
		};

		ws.isAlive = false;
		ws.ping();
	});
}, 3000);

playerServer.on('close', function close() {
	clearInterval(interval);
});

function disconnectAllPlayers(reqId, code, reason) {
	let clone = new Map(players);
	for (let player of clone.values()) {
		if (player.reqId === reqId) {
			player.ws.close(code, reason);
		}
	}
}


//Keep trying to send gameSessionId in case the server isn't ready yet
function sendGameSessionData() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	webRequest.get(`${FRONTEND_WEBSERVER}/server/requestSessionId`,
		function (response, body) {
			if (response.statusCode === 200) {
				gameSessionId = body;
				console.log('SessionId: ' + gameSessionId);
			}
			else {
				console.error('Status code: ' + response.statusCode);
				console.error(body);
			}
		},
		function (err) {
			//Repeatedly try in cases where the connection timed out or never connected
			if (err.code === "ECONNRESET") {
				//timeout
				sendGameSessionData();
			} else if (err.code === 'ECONNREFUSED') {
				console.error('Frontend server not running, unable to setup game session');
			} else {
				console.error(err);
			}
		});
}

function sendUserSessionData(serverPort) {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	webRequest.get(`${FRONTEND_WEBSERVER}/server/requestUserSessionId?gameSessionId=${gameSessionId}&serverPort=${serverPort}&appName=${querystring.escape(clientConfig.AppName)}&appDescription=${querystring.escape(clientConfig.AppDescription)}${(typeof serverPublicIp === 'undefined' ? '' : '&serverHost=' + serverPublicIp)}`,
		function (response, body) {
			if (response.statusCode === 410) {
				sendUserSessionData(serverPort);
			} else if (response.statusCode === 200) {
				userSessionId = body;
				console.log('UserSessionId: ' + userSessionId);
			} else {
				console.error('Status code: ' + response.statusCode);
				console.error(body);
			}
		},
		function (err) {
			//Repeatedly try in cases where the connection timed out or never connected
			if (err.code === "ECONNRESET") {
				//timeout
				sendUserSessionData(serverPort);
			} else if (err.code === 'ECONNREFUSED') {
				console.error('Frontend server not running, unable to setup user session');
			} else {
				console.error(err);
			}
		});
}

function sendServerDisconnect() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/serverDisconnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('serverDisconnected acknowledged by Frontend');
				} else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendServerDisconnect();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup user session');
				} else {
					console.error(err);
				}
			});
	} catch (err) {
		console.logColor(logging.Red, `ERROR::: sendServerDisconnect error: ${err.message}`);
	}
}

function sendPlayerConnectedToFrontend() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/clientConnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('clientConnected acknowledged by Frontend');
				} else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendPlayerConnectedToFrontend();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup game session');
				} else {
					console.error(err);
				}
			});
	} catch (err) {
		console.logColor(logging.Red, `ERROR::: sendPlayerConnectedToFrontend error: ${err.message}`);
	}
}

function sendPlayerDisconnectedToFrontend() {
	//If we are not using the frontend web server don't try and make requests to it
	if (!config.UseFrontend)
		return;
	try {
		webRequest.get(`${FRONTEND_WEBSERVER}/server/clientDisconnected?gameSessionId=${gameSessionId}&appName=${querystring.escape(clientConfig.AppName)}`,
			function (response, body) {
				if (response.statusCode === 200) {
					console.log('clientDisconnected acknowledged by Frontend');
				}
				else {
					console.error('Status code: ' + response.statusCode);
					console.error(body);
				}
			},
			function (err) {
				//Repeatedly try in cases where the connection timed out or never connected
				if (err.code === "ECONNRESET") {
					//timeout
					sendPlayerDisconnectedToFrontend();
				} else if (err.code === 'ECONNREFUSED') {
					console.error('Frontend server not running, unable to setup game session');
				} else {
					console.error(err);
				}
			});
	} catch (err) {
		console.logColor(logging.Red, `ERROR::: sendPlayerDisconnectedToFrontend error: ${err.message}`);
	}
}


