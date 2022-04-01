# tidy-api

tidy-api

## 1. Overview

tidy-api is a stateless, light-weight api protocol over http. It uses JSON (RFC 4627) as data format.

## 2. Http Request

### 2.1 Request method: MUST BE "POST"

### 2.2 Request headers:

- #### 'Content-Type': 'application/json; charset=UTF-8'
- #### 'X-TApi-Authorization' : TidyApiAuthorizationResult
  If the api does not require authentication, this header can be missing.

  see [TidyApiAuthorizationResult](#4-tidyapiauthorizationresult)

### 2.3 Request post body

A tidy-api call is represented by sending a Request post body to a Server. The Request post body is a JSON String of the
following object:

```typescript
{
    "tidyapi"
:
    1,
        "method"
:
    string,
        "params"
:
    any,
        "id"
:
    string
}
```

- **tidyapi**

  A number specifying the version of the tidy-api protocol. MUST be exactly 1.

- **method**

  A string containing the name of the method to be invoked.

- **params**

  A Structured value that holds the parameter values to be used during the invocation of the method.

- **id**

  A string request identifier established by the Client.

## 3. Http Response

When a tidy-api call is made, the Server MUST reply with a Response. The Response is expressed as a single JSON Object,
with the following members:

```typescript
type TidyHttpResponseBody = {
    "tidyapi": 1,
    "result"?: any,
    "error"?: TApiErrorObject,
    "id": string
}
```

- **tidyapi**

  A number specifying the version of the tidy-api protocol. MUST be exactly 1.

- **result**

  This member is REQUIRED on success.

  This member MUST NOT exist if there was an error invoking the method.

  The value of this member is determined by the method invoked on the Server.

- **error**

  This member is REQUIRED on error.

  This member MUST NOT exist if there was no error triggered during invocation.

  The value for this member MUST be an Object as defined in section [TidyApiErrorObject](#5-tidyapierrorobject).

- **id**

  This member is REQUIRED.

  It MUST be the same as the value of the id member in the Request Object.

## 4. TidyApiAuthorizationResult

**TidyApiAuthorizationResult** := Algorithm + ' ' + UnixSeconds + ' ' + **AccessKey** + ' ' + Signature

**Algorithm** := 'HS256'

**UnixSeconds** := the number of seconds that have elapsed since the Unix epoch

**Signature** := Base64(HMAC_SHA256(**SigningKey**, BinaryContentToSign))

**SigningKey** := SHA256(**EndPointName**+ ';' + UnixSeconds + ';' + **AccessSecret**)

**EndPointName** := the name of tidy-api endpoint

**BinaryContentToSign** :=

```js
Algorithm + ';' +
EndPointName + ';' +
SHA256(postBody) + ';' +
UnixSeconds.toString() + ';' +
AccessKey + ';' +
AccessSecret
```

## 5. TidyApiErrorObject

When a tidy-api call encounters an error, the Response Object MUST contain the error member with a value that is a
Object with the following members:

```typescript
{
    "code" ? : number,
        "message" ? : string,
        "data" ? : any
}
```

- **code**

  A Number that indicates the error type that occurred. This MUST be an integer.

  This may be omitted.

- **message**

  A String providing a short description of the error.

- **data**

  A Primitive or Structured value that contains additional information about the error.

  This may be omitted.

  The value of this member is defined by the Server (e.g. detailed error information, nested errors etc.).

