
//default state is false. 
let allowOutboundRequest = false;
let policy;
let cbFunction;
let attackMonitoring = false; // Default, not enabled.
let iscbFunctionDefined = false; //Default, not defined. When true, can change cbFUnction at runtime. 
let cbFuncitonLine = "at TLSSocket.obj.<computed> [as connect] (/mnt/c/Ironwasp/Product/NodeSecurityShield/lib/hook.js:22:13)"
//Error.stackTraceLimit = 60
var reportUriHosts = [];

/**
 * For outBoundRequest  , blockedDomains have greater presidence over allowedDomains. 
 * i.e., requests are checked against blockedDomains first then allowedDoamins.
 * 
 * @param {Object} policyJSON
 * @param {function} callbackFunction 
 */
let enableAttackMonitoring = function (policyJSON, callbackFunction) {
    policy = policyJSON;
    /**
     * Check if Call Back Funciton is already defined. 
     * If not defined assign it. 
     * If defiend, cant reassign untill server is restarted. 
     */
    if (!iscbFunctionDefined) {
        cbFunction = callbackFunction;
    }

    /**
     * If attackMonitoring not enbaled.
     */
    if (!attackMonitoring) {

        /**
         * Check for 'reportUriHosts' in RAP.
         * If exists populate reportUriHosts. 
         */
        if ("reportUriHosts" in policyJSON) {
            for (i = 0; i < policyJSON.reportUriHosts.length; i++) {
                reportUriHosts.push(policyJSON.reportUriHosts[i].trim())
            }
        }

        /**
         * Check for 'outBoundRequest' in RAP.
         * If exists and contains entries, 
         * then enable Attack Monitoring for all outbound requests.
         */
        if ("outBoundRequest" in policyJSON) {
            //todo: enable logging for policy file related exceptions
            const blockedArray = policyJSON.outBoundRequest.blockedDomains.map(e => e.trim());
            const allowedArray = policyJSON.outBoundRequest.allowedDomains.map(e => e.trim());

            if ((blockedArray.length + allowedArray.length) > 0) {

                //Enable attckMonitoring
                attackMonitoring = true;
                console.log('NSS : Attack Monitoring enabled. ');
                //blockedWildcardDomains => array of domains where all sub domains are blocked. (*)
                const blockedWildcardDomains = blockedArray.filter(domain => domain[0] == "*");
                //blockedDomains => array of domains to be blocked. (without wildcard) 
                const blockedDomains = blockedArray.filter(domain => domain[0] !== "*");
                //allowedWildcardDomains => array of domains where sub domains are allowd. (*)
                const allowedWildcardDomains = allowedArray.filter(domain => domain[0] == "*");
                //allowedDomains => array of domains which are allowed. (without wildcard)
                const allowedDomains = allowedArray.filter(domain => domain[0] !== "*");

                allowOutboundRequest = (outBoundReqDomain) => {

                    /**
                     * Allow outbound requests to reportUriHosts
                     */
                    for (i = 0; i < reportUriHosts.length; i++) {
                        if (outBoundReqDomain.endsWith(reportUriHosts[i])) {
                            return true
                        }
                    }

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


}

let checkSocketConnection = function (args) {

    let arg0;
    if (Array.isArray(args[0])) { //true if HTTP
        arg0 = args[0][0];
    } else {
        arg0 = args[0];
    }
    if (typeof arg0 === 'object' && arg0 !== null) {
        if (('port' in arg0) && ('host' in arg0)) { // TCP Connection.
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
        } else {
            //todo: log if there is no port or  no host in arguments. 
            //console.log(args)
            //console.log("Host and Port are not part of the argument passed to net.socket.connect")
        }
    }
}

let resourceAccessPolicyCheck = function (eventType, args) {
    //Check if attackMonitoring is enabled.
    if (attackMonitoring) {
        switch (eventType) {
            case 'socket':
                checkSocketConnection(args);
                break;
        }
    } else {
        //todo: provide detailed INFO logs. 
        //console.log('Attack Monitoring not enabled. ');
        //console.log('To enable : nodeSecurityShield.enableAttackMonitoring(resourceAccessPolicy ,callbackFunction)');
    }
}


module.exports = {
    enableAttackMonitoring: enableAttackMonitoring,
    resourceAccessPolicyCheck: resourceAccessPolicyCheck
}