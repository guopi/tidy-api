import crypto from 'crypto'

const SignAlgorithm = 'HS256'

export type TApiRequest = {
    method: string
    id: string
    params: any
}

export type TApiError = {
    code?: number
    message?: string
    data?: any
}

export type TApiSignatureOptions = {
    endPointName: string
    body: string
    unixSeconds: number
    accessKey: string
    accessSecret: string
}

export type TApiAuthorizationValidateResult = { error: TApiError } | {
    request: TApiRequest
    endPointName: string
    unixSeconds: number
    accessKey: string
}

export enum TApiErrorCode {
    InvalidAuthorization = 102,
    InvalidRequestObject = 103,
    InvalidTime = 104,
}

function createTApiSignatureKey(
    endPointName: string,
    unixSeconds: string,
    accessSecret: string
): Uint8Array {
    // SHA256(**EndPointName**+ ';' + UnixSeconds + ';' + **AccessSecret**)
    return sha256(`${endPointName};${unixSeconds};${accessSecret}`)
}

export function sha256(data: crypto.BinaryLike): Uint8Array {
    return crypto.createHash('sha256')
        .update(data)
        .digest()
}

/*
Signature** := Base64(HMAC_SHA256(**SigningKey**, BinaryContentToSign))
BinaryContentToSign :=
    Algorithm + ';' +
    EndPointName + ';' +
    SHA256(postBody) + ';' +
    UnixSeconds.toString() + ';' +
    AccessKey + ';' +
    AccessSecret
 */
export function createTApiSignature(
    endPointName: string,
    body: string,
    unixSeconds: string,
    accessKey: string,
    accessSecret: string,
): string {
    const hmac = crypto.createHmac('sha256',
        createTApiSignatureKey(endPointName, unixSeconds, accessSecret)
    )
    hmac.update(SignAlgorithm)
    hmac.update(';')
    hmac.update(endPointName)
    hmac.update(';')
    hmac.update(sha256(body))
    hmac.update(';')
    hmac.update(unixSeconds)
    hmac.update(';')
    hmac.update(accessKey)
    hmac.update(';')
    hmac.update(accessSecret)
    return hmac.digest('base64')
}

/**
 * TidyApiAuthorizationResult := Algorithm + ' ' + UnixSeconds + ' ' + AccessKey + ' ' + Signature
 */
export function createTidyApiAuthorizationHeader(
    endPointName: string,
    body: string,
    unixSeconds: number,
    accessKey: string,
    accessSecret: string,
): string {
    return SignAlgorithm
        + ' ' + unixSeconds
        + ' ' + accessKey
        + ' ' + createTApiSignature(
            endPointName,
            body,
            unixSeconds,
            accessKey,
            accessSecret,
        )
}

/**
 * @param headerValue : Algorithm + ' ' + UnixSeconds + ' ' + AccessKey + ' ' + Signature
 * @return success tuple or error
 */
function parseAuthorization(headerValue: string, maxSecondsGap: number): [unixSeconds: number, accessKey: string, signature: string] | TApiError {
    const parts = headerValue.split(' ')
    if (parts.length != 4) {
        return { code: TApiErrorCode.InvalidAuthorization, message: 'Invalid Authorization Format' }
    }

    const algorithm = parts[0]
    if (algorithm != SignAlgorithm) {
        return { code: TApiErrorCode.InvalidAuthorization, message: `Invalid Algorithm:${algorithm}` }
    }

    const unixSecondsText = parts[1]
    const unixSeconds = parseInt(unixSecondsText)
    if (Number.isNaN(unixSeconds)
        || !Number.isFinite(unixSeconds)
        || Math.abs(Date.now() / 1000 - unixSeconds) > maxSecondsGap
        || unixSeconds.toString() !== unixSecondsText
    ) {
        return { code: TApiErrorCode.InvalidTime, message: `Invalid Time:${unixSecondsText}` }
    }

    const accessKey = parts[2]
    if (!accessKey)
        return { code: TApiErrorCode.InvalidAuthorization, message: 'Missing AccessKey' }

    const signature = parts[3]
    if (!accessKey)
        return { code: TApiErrorCode.InvalidAuthorization, message: 'Missing Signature' }
    return [unixSeconds, accessKey, signature]
}

function parseTApiRequestWithSecret(
    authorization: [unixSeconds: number, accessKey: string, signature: string],
    endPointName: string,
    body: string,
    accessSecret: string
): TApiAuthorizationValidateResult {
    const unixSeconds = authorization[0]
    const accessKey = authorization[1]
    const requestSignature = authorization[2]
    if (createTApiSignature(
        endPointName,
        body,
        unixSeconds.toString(),
        accessKey,
        accessSecret,
    ) != requestSignature) {
        return { error: { code: TApiErrorCode.InvalidAuthorization, message: 'Invalid Signature' } }
    }

    let requestObject: any
    try {
        requestObject = JSON.parse(body)
    } catch (e) {
        return {
            error: {
                code: TApiErrorCode.InvalidRequestObject,
                message: `Invalid Request Body, error: ${e.toString()}`
            }
        }
    }

    if (requestObject == null || typeof requestObject !== 'object') {
        return {
            error: {
                code: TApiErrorCode.InvalidRequestObject,
                message: `Invalid type of Request Body: ${body}`
            }
        }
    }

    const tidyapi = requestObject.tidyapi
    if (tidyapi !== 1) {
        return {
            error: {
                code: TApiErrorCode.InvalidRequestObject,
                message: `Invalid Request member: tidyapi=${tidyapi}`
            }
        }
    }

    const method = requestObject.method
    if (typeof method !== 'string' || !method) {
        return {
            error: {
                code: TApiErrorCode.InvalidRequestObject,
                message: `Invalid Request member: method=${method}`
            }
        }
    }

    const id = requestObject.id
    if (typeof id !== 'string' || !id) {
        return {
            error: {
                code: TApiErrorCode.InvalidRequestObject,
                message: `Invalid Request member: id=${id}`
            }
        }
    }

    return {
        request: requestObject,
        endPointName: endPointName,
        unixSeconds,
        accessKey
    }
}

export function parseTApiRequest(
    endPointName: string,
    authorizationHeader: string,
    body: string,
    secretLoader: (accessKey: string) => string,
    maxSecondsGap: number = 300,
): TApiAuthorizationValidateResult {
    const authorization = parseAuthorization(authorizationHeader, maxSecondsGap)
    if (!Array.isArray(authorization))
        return { error: authorization }

    return parseTApiRequestWithSecret(
        authorization,
        endPointName,
        body,
        secretLoader(authorization[1])
    )
}

export async function parseTApiRequestAsync(
    endPointName: string,
    authorization: string,
    body: string,
    secretLoader: (accessKey: string) => Promise<string>,
    maxSecondsGap: number,
): Promise<TApiAuthorizationValidateResult> {
    const authorizationParts = parseAuthorization(authorization, maxSecondsGap)
    if (!Array.isArray(authorizationParts))
        return { error: authorizationParts }

    return parseTApiRequestWithSecret(
        authorizationParts,
        endPointName,
        body,
        await secretLoader(authorizationParts[1])
    )
}

