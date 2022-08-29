let resourceAccessPolicyCheck = require('./attackMonitoring').resourceAccessPolicyCheck;

let isHooked =  false;

let initHooks = function(){
    //console.log('Initilizing Node Security Shield Hooks')
    if(!isHooked){
        isHooked = true;
        hookSocket();
        hookCmd();
    }
}

let hookSocket = function(){
    let methodName = "connect";
    let obj = require('net').Socket.prototype;
    let original = obj[methodName];
    obj[methodName] = function () {
        if (arguments.length > 0) {
            let stack = new Error().stack;
            resourceAccessPolicyCheck('socket', arguments, stack);
        }
        return original.apply(this, arguments);
    };
}

let hookCmd = function(){
        //async
        let methodName = "spawn";
        let obj = require('child_process').ChildProcess.prototype;
        let original = obj[methodName];
        obj[methodName] = function () {
            if (arguments.length > 0) {
                let stack = new Error().stack;
                resourceAccessPolicyCheck('command', arguments, stack);
            }
            return original.apply(this, arguments);
        };
        //sync
        let obj1 = process.binding('spawn_sync');
        let original1 = obj1[methodName];
        obj1[methodName] = function () {
            if (arguments.length > 0) {
                let stack = new Error().stack;
                resourceAccessPolicyCheck('command', arguments, stack);
            }
            return original1.apply(this, arguments);
        };

}



module.exports = {
    initHooks : initHooks
}
