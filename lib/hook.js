let resourceAccessPolicyCheck = require('./attackMonitoring').resourceAccessPolicyCheck;

let isHooked =  false;

let initHooks = function(){
    //console.log('Initilizing Node Security Shield Hooks')
    if(!isHooked){
        isHooked = true;
        hookSocket();
        
    }
}

let hookSocket = function(){
    //console.log('-> Hooking Socket')
    let methodName = "connect";
    let obj = require('net').Socket.prototype;
    let original = obj[methodName];
    obj[methodName] = function () {
        if (arguments.length > 0) {
            resourceAccessPolicyCheck('socket', arguments);
        }
        return original.apply(this, arguments);
    };
}
module.exports = {
    initHooks : initHooks
}