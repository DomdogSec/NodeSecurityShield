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
    let methodName = "connect";
    let obj = require('net').Socket.prototype;
    let original = obj[methodName];
    obj[methodName] = function () {
        if (arguments.length > 0) {
            let stack = new Error().stack;
            const lines = stack.split('\n').slice(1);
            stack = lines.map(function(line){
                const lineMatch = line.match(/at (?:(.+?)\s+\()?(?:(.+?):(\d+)(?::(\d+))?|([^)]+))\)?/);
                const fileName  = lineMatch[2];
                return fileName;
            }).join('\n');
            resourceAccessPolicyCheck('socket', arguments, stack);

        }
        return original.apply(this, arguments);
    };
}
module.exports = {
    initHooks : initHooks
}
