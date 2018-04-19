const request = require('request');
const yargs = require('yargs');


console.log('Start');

request({
  url:'https://maps.googleapis.com/maps/api/geocode/json?address='+'via+Cascine+41+Cittiglio+Italy',
  json:true
},(error,response,body)=>{
  console.log(body);
  console.log(JSON.stringify(body));
  if (error) console.log(error);
})
