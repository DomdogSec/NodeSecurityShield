/**
 * For outBoundRequest  , blockedDomains has greater presidence over allowedDomains. 
 * i.e., request will be checked against blockedDomains first then followed allowedDoamins.
 * {
    "blockedDomains" : ["*.google.com", "*.ndtv.com", "*.sboxr.com"],
    "allowedDomains" : ["*.w3schools.com"]
    }
 * 
 * @param {Object} policyJSON
 * @param {function} callbackFunction 
 */


 function enableAttackMonitoring(policyJSON, callbackFunction) {
    
    
    //Enable AttackMonitoring For OutBoud Requests. 
    if ("outBoundRequest" in policyJSON){
        
        //todo: enable logging for policy file related exceptions
        const blockedArray = policyJSON.outBoundRequest.blockedDomains.map(e=>e.trim());
        const allowedArray = policyJSON.outBoundRequest.allowedDomains.map(e=>e.trim());
        
        //Only if there are entries in policy for outBoundRequests. 
        if ((blockedArray.length + allowedArray.length) > 0){
            
            //Default state false. 
            let allowOutboundRequest = false; 

            //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
            const blockedWildcardDomains = blockedArray.filter(domain => domain[0] == "*");
            //blockedDomains => array of domains to be blocked. (without wildcard) 
            const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
            //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
            const allowedWildcardDomains = allowedArray.filter(domain => domain[0] == "*");
            //allowedDomains => array of domains which are allowed. (without wildcard)
            const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");
            allowOutboundRequest = (outBoundReqDomain) => {
                if (blockedArray.length > 0){
                    //check outbound request in blockedDomains (without wildcard)
                    if(outBoundReqDomain in blockedDomains){
                        //Outbound Request not allowed 
                        return false;
                    }else{//check outbound request in blockedWildcardDomains
                        for (i=0; i < blockedWildcardDomains.length; i++) {
                            let wildcardDomain = blockedWildcardDomains[i].split('*').pop();
                            if (outBoundReqDomain.length > wildcardDomain.length) {
                                if(outBoundReqDomain.substr(outBoundReqDomain.length - wildcardDomain.length) == wildcardDomain){
                                    //Outbound Request not allowed
                                    return false; 
                                }   
                            }
                        }
                    }
                }
                if(allowedArray.lenght > 0){
                    //check outbound request in allowedDomains (without wildcard)
                    if(outBoundReqDomain in allowedDomains){
                        //Outbound Request allowed 
                        return true;
                    }else{ // check outbound request in allowedWildcardDomains 
                        for (i=0; i<allowedWildcardDomains.length; i++) {
                            let wildcardDomain = allowedWildcardDomains[i].split('*').pop();
                            if (outBoundReqDomain.length > wildcardDomain.length) {
                                if(outBoundReqDomain.substr(outBoundReqDomain.length - wildcardDomain.length) == wildcardDomain){
                                    //Outbound Request allowed
                                    return true; 
                                }   
                            }
                        }
                    }
                }
                //default state is to block.
                return false;
            }

            //Monitor Outbound Requests
            let methodName = "connect";
            let obj = require('net').Socket.prototype;
            let original = obj[methodName];
            obj[methodName] = function () {
                if (arguments.length > 0) {
                    let arg0 = arguments[0];
                    //console.log(arguments);
                    //todo: below implimentation fails in few cases. (making outbound requests using require('http')). 
                    //todo: reason being, host and port at accesible at arg0[0]
                    if (typeof arg0 === 'object' && arg0 !== null) {
                        //console.log(arg0)
                        //console.log(new Error().stack);
                        if (arg0.hasOwnProperty('port') && arg0.hasOwnProperty('host')) { // TCP Connection mostly outward
                            
                            if(!allowOutboundRequest(arg0.host)){
                                //todo: throw event for ResourceIntensiveEventTracing
                                let violationEvent = {};
                                violationEvent.violationtType = "Outbound Request";
                                //todo: include details of domain being part of blockedList or not being part of allowedList caused he violation. 
                                //todo: maybe return a message and boolean.
                                violationEvent.message = `Outbound request to '${arg0.host}' violates declared 'Resource Access Policy (RAP)'.`;
                                violationEvent.policy = policyJSON;
                                //Let callbackFunction decide what to be done with violation event.
                                callbackFunction(violationEvent);
                            }else{
                                //todo: throw event for ResourceIntensiveEventTracing
                                
                            }
                        } /*else if (arg0.hasOwnProperty('port') && !arg0.hasOwnProperty('host')) { // TCP Connection within localhost
                            //console.log("localhost:" + arg0['port']);
                            //todo: throw event for ResourceIntensiveEventTracing
                        } else if (arg0.hasOwnProperty('path')) { // IPC conneeciton
                            //todo: throw event for ResourceIntensiveEventTracing
                        }*/
                    }
                }

                return original.apply(this, arguments);
            };
        }

        
    }
    
}
  
module.exports = enableAttackMonitoring;

