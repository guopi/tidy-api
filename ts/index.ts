import crypto from 'crypto'

const SignAlgorithm = 'HS256'

export type TidyApiRequest = {
    method: string
    id: string
    params: any
}

export type TidyApiError = {
    code?: number
    message?: string
    data?: any
}

export type TidyApiSignatureOptions = {
    endPointName: string
    method: string
    body: string
    unixSeconds: number
    accessKey: string
    accessSecret: string
}

export type AuthorizationValidateResult = { error: TidyApiError } | {
    request: TidyApiRequest
    endPointName: string
    unixSeconds: number
    accessKey: string
}

export enum ErrorCode {
    InvalidSchema = 101,
    InvalidCommand = 102,
    InvalidSign = 103,
    InvalidTime = 104,
    HttpError = 105,
}

export function createTidyApiSignatureKey(options: TidyApiSignatureOptions): Uint8Array {
    // SHA256(**EndPointName**+ ';' + UnixSeconds + ';' + **AccessSecret**)
    return sha256(`${options.endPointName};${options.unixSeconds};${options.accessSecret}`)
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
export function createTidyApiSignature(options: TidyApiSignatureOptions): string {
    const hmac = crypto.createHmac('sha256', createTidyApiSignatureKey(options))
    hmac.update(SignAlgorithm)
    hmac.update(';')
    hmac.update(options.endPointName)
    hmac.update(';')
    hmac.update(sha256(options.body))
    hmac.update(';')
    hmac.update(options.unixSeconds.toString())
    hmac.update(';')
    hmac.update(options.accessKey)
    hmac.update(';')
    hmac.update(options.accessSecret)
    return hmac.digest('base64')
}

/**
 * TidyApiAuthorizationResult := Algorithm + ' ' + UnixSeconds + ' ' + AccessKey + ' ' + Signature
 */
export function createTidyApiAuthorizationHeader(options: TidyApiSignatureOptions): string {
    return SignAlgorithm
        + ' ' + options.unixSeconds
        + ' ' + options.accessKey
        + ' ' + createTidyApiSignature(options)
}

function parseAuthorizationHeader(authorization: string): [unixSeconds: number, accessKey: string, signature: string] | string {
    const parts = authorization.split(' ')

}

export function validateTidyApiAuthorization(endPointName: string, authorization: string, body: string, secretFinder: (key: string) => string): AuthorizationValidateResult {

    return {}
}

