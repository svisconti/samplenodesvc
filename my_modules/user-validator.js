var fs = require('fs');
var lineReader = require('readline');
var parse = require('csv-parse/lib/sync');
var SHA256 = require('crypto-js/sha256');
var AES = require('crypto-js/aes');
var crypto = require('crypto-js');
var qs = require('querystring');
const winston = require('winston');

var logger = new winston.Logger({
  transports: [
    new winston.transports.File({
      level: 'info',
      filename: 'log/all.log',
      timestamp: function() { return (new Date()).toISOString(); }
    })
  ]
});


function generateCredentials (privateKey,user){
      //crypt userid for easier transport in GET
      var cuserid = AES.encrypt(user.userid+"",privateKey).toString();
      //encode for userid
      cuserid = qs.escape(cuserid);
      var cred = {
        "cuserid": cuserid,
        "x-auth": SHA256(user.userid+":"+privateKey).toString()
      };
      return cred;
  }

function  validateCredentials(privateKey,ecuserid,xauth){
    try {
      var cuserid = qs.unescape(ecuserid);
      var puserid = AES.decrypt(cuserid+"",privateKey).toString(crypto.enc.Utf8);
      var xa = SHA256(puserid+":"+privateKey).toString();
      if (xa === xauth){
        logger.info("Credentials are valid for user "+puserid);
        return true;
      }
      else {
        console.log("False Credentials userid="+puserid);
        return false;
      }
    } catch (err){
      console.log(err);
      console.log("Error validating credentials cuserid="+cuserid+",puserid="+puserid+",xa="+xa);
      return false;
    }
  }

function  isUserValid(user){
          var userid = user.userid;
          var p = new Promise( function(resolve,reject){

              var rl = lineReader.createInterface({
                input: fs.createReadStream('conf/validusers.csv')
              });

              var result = false;
              rl.on('line', function (line) {
                //console.log('Line from file:', line);
                var output = parse(line, { comment: '#', columns: ["userid","name"], delimiter: "," });
                if (output[0]){
                   if (output[0].userid==userid) result = true;
                   //console.log(output[0].userid+"=>"+output[0].name);
                }
              });
              rl.on('error', function (err) {
                console.log(err);
                rl.close();
                reject(err);
              });
              rl.on('close', () => {
                //console.log('close file');
                resolve(result);
              });

        });
        return p;
}


module.exports = { generateCredentials, isUserValid, validateCredentials, logger };

//var cred = generateCredentials("sddsdasdadssd",{userid:"1212"});
//validateCredentials("sddsdasdadssd",cred.cuserid,cred.xauth);
/*var valid = false;
isUserValid("1102012").then((result)=>{valid = result;});
console.log("Result = "+valid);
res2=isUserValid("11");
console.log("Result = "+res2);*/
