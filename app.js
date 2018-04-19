const express = require('express');
const fs = require('fs');
const uv = require('./my_modules/user-validator')
const http = require('http');
const https = require('https');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const rfs = require ('rotating-file-stream');

var logger = uv.logger;

//generated self-signed with
//openssl req -x509 -sha256 -nodes -newkey rsa:2048 -days 365 -keyout server.key -out server.crt

var privateKey  = fs.readFileSync('sslcert/server.key', 'utf8');
var certificate = fs.readFileSync('sslcert/server.crt', 'utf8');
var options = {
    key: privateKey,
    cert: certificate,
    ciphers: 'ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES256-SHA384',
    honorCipherOrder: true,
    secureProtocol: 'TLSv1_2_method'
};

var app = express();
app.use(helmet());
var logdir = path.join(__dirname,'log');
fs.existsSync(logdir) || fs.mkdirSync(logdir);
var accesslog=rfs('access.log', { interval: '1d', path: logdir});
app.use(morgan("tiny",{stream:accesslog}));




app.get('/download', function(req, res){
  var xauth = req.headers['x-auth'];
  var cuserid = req.query.cuserid;
  if (typeof xauth === "undefined" || typeof cuserid === "undefined" || !uv.validateCredentials(privateKey,cuserid,xauth)){
    res.status(401);
    res.send("Invalid request");
    return;
  }

  var fname = req.query.fname;
  var folder = req.query.folder;
  if (typeof fname === "undefined" || fname.indexOf('/')>-1 || fname.indexOf('\\')>-1 || fname.indexOf("..")>-1) {
    res.status(401);
    res.send("Invalid request");
    return;
  }
  var pfolder=""; //final polished folder name
  if (typeof folder === "undefined" || folder.indexOf('/')>-1 || fname.indexOf('\\')>-1 || fname.indexOf("..")>-1){
    pfolder="/";
  }
  else {
    pfolder = "/"+folder+"/";
  }
  var file = __dirname + '/downloads'+pfolder+fname;
  if (!fs.existsSync(file)) {
    res.status(404);
    res.send("File not found '"+fname+"'");
    return;
  }

  logger.info('Downloading file '+file);
  res.download(file); // Set disposition and send it.

});


app.post('/auth', (req,res) => {
  try {
      var jsonbody = "";
      req.on('data',function(data){
          jsonbody+=data;
      });
      req.on('end',function(){
        if (jsonbody== ""){
          logger.warn("Empty request");
          res.sendStatus(401);
        }
        else {
          var user=JSON.parse(jsonbody);
          uv.isUserValid(user).then((result)=>{
              if (result) {
                res.send(JSON.stringify(uv.generateCredentials(privateKey,user)));
                logger.info("Authorization SUCCESS for user "+user.userid);
              }
              else {
                res.sendStatus(401);
                logger.info("Authorization FAILED for user ="+user.userid);
              }
          }).catch((err)=>{throw err;});
        }
      });

  } catch (err){
    res.sendStatus(500);
    logger.error(err);
  }
});

var httpServer = http.createServer(app);
httpServer.listen(8080);

var httpsServer = https.createServer(options, app);
httpsServer.listen(8443);
