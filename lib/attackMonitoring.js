
//default state is false. 
let allowOutboundRequest = false;
let policy;
let cbFunction;

/**
 * For outBoundRequest  , blockedDomains have greater presidence over allowedDomains. 
 * i.e., requests are checked against blockedDomains first then allowedDoamins.
 * 
 * @param {Object} policyJSON
 * @param {function} callbackFunction 
 */
let enableAttackMonitoring = function (policyJSON, callbackFunction) {
    policy = policyJSON;
    cbFunction = callbackFunction;

    //Enable AttackMonitoring For OutBoud Requests. 
    if ("outBoundRequest" in policyJSON) {

        //todo: enable logging for policy file related exceptions
        const blockedArray = policyJSON.outBoundRequest.blockedDomains.map(e => e.trim());
        const allowedArray = policyJSON.outBoundRequest.allowedDomains.map(e => e.trim());

        //Only if there are entries in policy for outBoundRequests. 
        if ((blockedArray.length + allowedArray.length) > 0) {

            //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
            const blockedWildcardDomains = blockedArray.filter(domain => domain[0] == "*");
            //blockedDomains => array of domains to be blocked. (without wildcard) 
            const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
            //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
            const allowedWildcardDomains = allowedArray.filter(domain => domain[0] == "*");
            //allowedDomains => array of domains which are allowed. (without wildcard)
            const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");

            allowOutboundRequest = (outBoundReqDomain) => {

                if (blockedArray.length > 0) {
                    //check outbound request in blockedDomains (without wildcard)
                    if (outBoundReqDomain in blockedDomains) {
                        //Outbound Request not allowed 
                        return false;
                    } else {//check outbound request in blockedWildcardDomains
                        for (i = 0; i < blockedWildcardDomains.length; i++) {
                            let wildcardDomain = blockedWildcardDomains[i].split('*').pop();
                            if (outBoundReqDomain.length > wildcardDomain.length) {
                                if (outBoundReqDomain.substr(outBoundReqDomain.length - wildcardDomain.length) == wildcardDomain) {
                                    //Outbound Request not allowed
                                    return false;
                                }
                            }
                        }
                    }
                }
                if (allowedArray.lenght > 0) {
                    //check outbound request in allowedDomains (without wildcard)
                    if (outBoundReqDomain in allowedDomains) {
                        //Outbound Request allowed 
                        return true;
                    } else { // check outbound request in allowedWildcardDomains 
                        for (i = 0; i < allowedWildcardDomains.length; i++) {
                            let wildcardDomain = allowedWildcardDomains[i].split('*').pop();
                            if (outBoundReqDomain.length > wildcardDomain.length) {
                                if (outBoundReqDomain.substr(outBoundReqDomain.length - wildcardDomain.length) == wildcardDomain) {
                                    //Outbound Request allowed
                                    return true;
                                }
                            }
                        }
                    }
                }
                //default state is to false.
                return false;
            }

        }


    }

}

let checkSocketConnection = function (args) {
    let arg0 = args[0][0];
    //console.log(arguments);
    //todo: below implimentation fails in few cases. (making outbound requests using require('needle')). 
    //todo: reason being, host and port at accesible at args[0] , not args[0][0]
    if (typeof arg0 === 'object' && arg0 !== null) {
        if (arg0.hasOwnProperty('port') && arg0.hasOwnProperty('host')) { // TCP Connection mostly outward
            if (!allowOutboundRequest(arg0.host)) {
                let violationEvent = {};
                violationEvent.violationtType = "Outbound Request";
                //todo: include details of domain being part of blockedList or not being part of allowedList caused he violation. 
                //todo: maybe return a message and boolean.
                violationEvent.message = `Outbound request to '${arg0.host}' violates declared 'Resource Access Policy (RAP)'.`;
                violationEvent.policy = policy;
                //Let callbackFunction decide what to be done with violation event.
                cbFunction(violationEvent);
            }
        }
    }
}

let resourceAccessPolicyCheck = function (eventType, args) {
    switch (eventType) {
        case 'socket':
            checkSocketConnection(args);
            break;
    }
}


module.exports = {
    enableAttackMonitoring: enableAttackMonitoring,
    resourceAccessPolicyCheck: resourceAccessPolicyCheck
}
