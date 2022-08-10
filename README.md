<img src="/assets/images/NodeSecurityShield.png" width="200px" height="250px">


# Node Security Shield

**Node Security Shield (NSS)** is an Open source Runtime Application Self-Protection (**RASP**) tool which aims at bridging the gap for comprehensive NodeJS security by enabling *Developer* and *Security Engineer* to declare what resources an application can access.

Inspired by the Log4Shell  ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) vulnerability which can be exploited because an application can make arbitrary network calls, we felt there is a need for an application to have a mechanism so that it can declare what privileges it allows in order to make the exploitation of such vulnerabilities harder by implementing additional controls.

In order to achieve this, **NSS (Node Security Shield)** has **Resource Access Policy (RAP)**

### Resource Access Policy (RAP)

**Resource Access Policy** is similar to **CSP**([Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)).

It lets the developer/security engineer declare what resources an application should access. And **Node Security Shield** will enforce it.

## Installation

Clone the repository 

```
git clone https://github.com/DomdogSec/NodeSecurityShield
```

Install *NSS* using npm

```
  npm install <path-to-cloned-repository>
```

## Usage

```
// Require Node Security Shield
let nodeSecurityShield = require('nodesecurityshield');

// Enable Attack Monitoring and/or Blocking
nodeSecurityShield.enableAttackMonitoring("Unique-App-Id",resourceAccessPolicy ,callbackFunction);
```

**Sample *resourceAccessPolicy [BASIC]***

```
const resourceAccessPolicy  = {
  "outBoundRequest" : {

      "blockedDomains" : ["compromised.domdog.io"],
    
      "allowedDomains" : []
    }
};
```

- **Note:** blockedDomains holds precedence over allowedDomains.
- **i.e.,** requests checked against blockedDomains first then allowedDomains.

**Sample *callbackFunction* to log RAP violations to conosle.**

```
var callbackFunction = function (violationEvent,violations,violationLimitPerMinReached) {
  console.log(JSON.stringify(violationEvent,null, 4));
}
```

- ***violationEvent -** RAP violation which occurred. It is presented as a CSP violation.*
- ***violations -** RAP violation count. Resets to ZERO every minute.*
- ***violationLimitPerMinReached -** true if RAP violations count exceeds 'maxViolationsPerMinute’ [ an option in RAP]*
- ****To Block an Attack** - throw an error

    `throw new Error("Request Blocked. It violates declared Resource Access Policy.")`

**Sample violationEvent**

```
{
    "csp-report": {
        "document-uri": "https://Unique-App-Id",
        "blocked-uri": "https://compromised.domdog.io:443",
        "violated-directive": "connect-src",
        "effective-directive": "connect-src",
        "original-policy": "{\"outBoundRequest\":{\"blockedDomains\":[\"compromised.domdog.io\"],\"allowedDomains\":[]}}",
        "disposition": "report",
        "status-code": 200,
        "script-sample": "",
        "source-file": "Error\n    at TLSSocket.obj.<computed> [as connect] (/mnt/c/Ironwasp/Product/NodeSecurityShield/lib/hook.js:20:25)\n    at Object.connect (_tls_wrap.js:1606:13)\n    at Agent.createConnection (https.js:126:22)\n    at Agent.createSocket (_http_agent.js:273:26)\n    at Agent.addRequest (_http_agent.js:232:10)\n    at new ClientRequest (_http_client.js:302:16)\n    at request (https.js:310:10)\n    at Object.get (https.js:314:15)\n    at /mnt/c/Ironwasp/RD/Node/SimpleVulnerableNode/routes/ssrf.js:19:19\n    at Layer.handle [as handle_request] (/mnt/c/Ironwasp/RD/Node/SimpleVulnerableNode/node_modules/express/lib/router/layer.js:95:5)"
    }
}
```

- **document-uri :** contains Unique-App-Id , passed during initialization of NSS
- **blocked-uri :** domain of the outbound request which violated RAP
- **violated-directive :** `connect-src` is synonym for `Outbout Request`
- **original-policy :** violated Resource Access Policy (RAP)
- **source-file :** Stack Trace of where this violation.

## Integrating with Sentry

**Sample *resourceAccessPolicy to integrate with [Sentry](https://sentry.io/)***

```
const resourceAccessPolicy  = {
  "outBoundRequest" : {

      "blockedDomains" : ["compromised.domdog.io"],
    
      "allowedDomains" : []
    },
"reportUri": "https://ingest.sentry.io/api/6011856/security/?sentry_key=",

};
```

- **reportUri :** Sends Violations to a given endpoint.
As violations are similar to Content Security Policy violations. Any CSP monitoring solutions can be used. 
We used the Sentry endpoint in the above RAP.

**Screenshot from Sentry dashboard**
![sentry issues](/assets/screenshots/Sentry1.png)
![sentry issues](/assets/screenshots/Sentry.png)

**Sample *resourceAccessPolicy [Advanced]***

```
const resourceAccessPolicy = {
    "outBoundRequest" : {
    
        "blockedDomains" : ["compromised.domdog.io"],
        
        "allowedDomains" : ["domdog.io","*.domdog.io", 
           
            {
                "domains": [
                    "domgo.at",
                ],
                "modules": [
                    {
                        "file": "\/routes\/ssrf.js",
                    },
                    {
                        "file": "\/node_modules\/axios\/",
                    }
                ]
            },
            {
                "domains": [
                    "cluster0-shard-00-00.lb9jm.mongodb.net",
                    "cluster0-shard-00-01.lb9jm.mongodb.net",
                    "cluster0-shard-00-02.lb9jm.mongodb.net"
                ],
                "modules": [
                    {
                        "file": "\/node_modules\/mongodb\/"
                    }
                ]
            }
          
        ]
    },
    
    "reportUri": "https://endpoint-to-send-violations",
    
    "maxViolationsPerMinute": 50
  }
```

- **Note:** blockedDomains holds precedence over allowedDomains.
- **Module Specific Control :** allowedDomain Array accepts Objects with following
    - **domain :**  Array of domains which are to be allowed for provided files.
    - **modules :** Array of Objects containing file paths. Only outbound Requests made through these files to specified domains are allowed.
- **reportUri :** Sends Violations to a given endpoint.
As violations are similar to Content Security Policy violations. Any CSP monitoring solutions can be used.
- **maxViolationsPerMinute :** Maximum number of violations to be sent to the reportUri.  
If not specified, the default value (*100 violations*) is used.

## Features

- **Attack Monitoring**
    - Outbound Network Calls
- **Attack Blocking**
    - Outbound Network Calls
- **Module Specific Control**


## Roadmap

- **Attack Monitoring**
    - Command Execution
    - File Calls
- **Attack Blocking**
    - Command Execution
    - File Calls
- **Vulnerability Scanner**



## Authors

- Lavakumar Kuppan  
    - Github    - [@lavakumar](https://github.com/Lavakumar)
    - Twitter   - [@lavakumark](https://twitter.com/lavakumark)
- Sukesh Pappu  
    - Github    - [@thelogicalbeard](https://www.github.com/thelogicalbeard)
    - Twitter   - [@thelogicalbeard](https://www.twitter.com/thelogicalbeard)




## Contributors

- Ayusman Samal
    - Github - [@p1xxxel](https://github.com/p1xxxel)



## License

[Apache License 2.0](/LICENSE)

