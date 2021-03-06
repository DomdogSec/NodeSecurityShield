<img src="/assets/images/NodeSecurityShield.png" width="200px" height="250px">


# Node Security Shield

A Developer and Security Engineer friendly package for Securing NodeJS Applications.

Inspired by the log4J vulnerability ([CVE-2021-44228](https://nvd.nist.gov/vuln/detail/CVE-2021-44228)) which can be exploited because an application can make arbitrary network calls.

We felt there is an need for an application to declare what privileges it can have so that exploitation of such vulnerabilities becomes harder.

To achieve this, **NSS** (__Node Security Shield__) has **Resource Access Policy**.


### Resource Access Policy (RAP)
**Resource Access Policy** is similar to **CSP**([Content Security Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)).

It lets the developer/security engineer declare what resources an application should access. And **Node Security Shield** will enforce it.



## Installation

Install *Node Security Shield* using npm

```bash
  npm install nodesecurityshield
```
    
## Usage

```javascript
// Require Node Security Shield
let nodeSecurityShield = require('nodesecurityshield');

// Enable Attack Monitoring and/or Blocking
nodeSecurityShield.enableAttackMonitoring(resourceAccessPolicy ,callbackFunction);
```

**Sample *resourceAccessPolicy***
```javascript
const resourceAccessPolicy  = {
  "outBoundRequest" : {
          "blockedDomains" : ["*.123.com", "stats.abc.com", 'xyz.com'],
          "allowedDomains" : ["*.domdog.io"]
      }
};
```
* **Note:** blockedDomains holds precedence over allowedDomains.
* **i.e.,** requests checked against blockedDomains first then allowedDomains.

**Sample *callbackFunction* for Attack Monitoring**
```javascript
var callbackFunction = function (violationEvent) {
  console.log(violationEvent);
}
```

**Sample *callbackFunction* for Attack Blocking**
```javascript
var callbackFunction = function (violationEvent) {
    throw new Error("Request Blocked. It violates declared Resource Access Policy.")
}
```

**Sample violationEvent**
```javascript
{
 "violationtType": "Outbound Request",
 "message": "Outbound request to 'www.malicious.com' violates declared 'Resource Access Policy (RAP)'.",
 "policy": {
  "outBoundRequest" : {
          "blockedDomains" : ["*.123.com", "stats.abc.com", 'xyz.com'],
          "allowedDomains" : ["*.domdog.io"]
      }
}
```

### Integrating with Sentry
**Sample *resourceAccessPolicyto integrate with [Sentry](https://sentry.io)***
```javascript
const resourceAccessPolicy  = {
  "reportUriHosts" : ["ingest.sentry.io"],
  "outBoundRequest" : {
          "blockedDomains" : ["*.123.com", "stats.abc.com", 'xyz.com'],
          "allowedDomains" : ["*.domdog.io"]
      }
};
```
* **Note:** reportUriHosts is an array of hosts to which reports are sent. Similar to report-uri directive in CSP. 
* **Note:** blockedDomains holds precedence over allowedDomains.
* **i.e.,** requests checked against blockedDomains first then allowedDomains.

**Sample *callbackFunction to integrate with [Sentry](https://sentry.io)***
```javascript
var callbackFunction = function (violationEvent) {
  
  var e = new Error();
  e.name = 'Resource Access Policy Violation';
  e.message = JSON.stringify(violationEvent);
  Sentry.captureException(e);

}
```
**Screenshot from Sentry dashboard**
![sentry issues](/assets/screenshots/Sentry1.png)

## Features

- **Attack Monitoring**
    - Outbound Network Calls
- **Attack Blocking**
    - Outbound Network Calls

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



## License

[Apache License 2.0](/LICENSE)

