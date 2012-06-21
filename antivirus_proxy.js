//
// A Anti-Virus HTTP proxy for node.js  (or IGK for node.js :-) )
// You need "fsav" command in F-Secure Anti-Virus (Linux or Mac)
//	or "clamdscan" command in ClamXav
//   by Yoshioka Tsuneo (yoshiokatsuneo@gmail.com)
//
// Usage: node antivirus_proxy.js [--scanner=f-secure|clamav] [--listen_port=xxxx]
//

var url = require('url');
var http = require('http');
var child_process = require('child_process');
var fs = require('fs');

var scanner = "f-secure"; // "f-secure" or "clamav"
var listen_port = 9080;

process.argv.forEach(function(val, index, array){
	if(val.match("--([^=]*)=(.*)")){
		eval(RegExp.$1 + "='" + RegExp.$2 + "'");
	}
});


var scanner_cmd;
var scanner_args;
if(scanner == "f-secure"){
	process.env.PATH += ":/usr/local/f-secure/fssp/bin:/opt/f-secure/fssp/bin";
	scanner_cmd = "fsav";
	scanner_args = ["--socketname=/tmp/fsav-nodeigk", "--action1=none"];
}else if(scanner == "clamav"){
	process.env.PATH += ":/usr/local/clamXav/bin";
	scanner_cmd = "clamdscan";
	scanner_args = [];
}else{
	console.log("Unknown scanner: " + scanner);
}
console.log("Scanner: " + scanner);
console.log("Scanner command: " + scanner_cmd);

var proxy = http.createServer(function(client_req, client_res){
	console.log("request:" + client_req.url + " / " + JSON.stringify(client_req.headers));
	delete client_req.headers['accept-encoding'];
	var urlobj = url.parse(client_req.url);
	var options = {
		host: urlobj.host,
		port: urlobj.port,
		method: client_req.method,
		path: urlobj.path,
		headers: client_req.headers,
		httpVersion: "1.0",
		};
	var server_req = http.request(options, function(server_response){
		var server_response_body = "";

		// does not scan on status code other than 200.
		var cutthrough = (server_response.statusCode != 200);
		if(cutthrough){
			client_res.writeHead(server_response.statusCode, server_response.headers);
		}
		server_response.on('data', function(chunk){
			if(cutthrough){
				client_res.write(chunk);
			}else{
				server_response_body = server_response_body + chunk;
			}
		});
		server_response.on('end', function(){
			if(cutthrough){
				client_res.end();
			}else{
				var detection_name = "";
				fs.writeFileSync("/tmp/nodeigk-response-body.tmp", server_response_body);
				var fsav = child_process.spawn(scanner_cmd, scanner_args.concat(["/tmp/nodeigk-response-body.tmp"]));
				fsav.stdout.on('data', function(data){
					if(scanner == "f-secure"){
						if(data.toString().match("Infected:(.*)")){
							detection_name = RegExp.$1;
						}
					}else if(scanner == "clamav"){
						if(data.toString().match(": (.*) FOUND")){
							detection_name = RegExp.$1;
						}
					}
				});
				fsav.stderr.on('data', function(data){
					console.log("fsav stderr:" + data);
				});
				fsav.on('exit', function(code, signal){
					if(code == 0){
						client_res.writeHead(server_response.statusCode, server_response.headers);
						client_res.end(server_response_body);
					}else{
						client_res.writeHead(200, {'Content-Type': 'text/html'});
						client_res.end("Virus Found: " + detection_name);
					}
				});
			}
		});
	});
	client_req.on('data', function(chunk){
		server_req.write(chunk);
	});
	client_req.on('end', function(){
		server_req.end();
	});
});

console.log("Listening on port: " + listen_port);
proxy.listen(listen_port);

