"use strict";
(self["webpackChunkwalinga_github_io"] = self["webpackChunkwalinga_github_io"] || []).push([[207],{

/***/ 207:
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {


// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  CognitoIdentityClient: () => (/* reexport */ CognitoIdentityClient/* CognitoIdentityClient */.D),
  GetCredentialsForIdentityCommand: () => (/* reexport */ GetCredentialsForIdentityCommand),
  GetIdCommand: () => (/* reexport */ GetIdCommand)
});

// EXTERNAL MODULE: ./node_modules/@smithy/middleware-endpoint/dist-es/index.js + 8 modules
var dist_es = __webpack_require__(12);
// EXTERNAL MODULE: ./node_modules/@smithy/middleware-serde/dist-es/index.js + 3 modules
var middleware_serde_dist_es = __webpack_require__(208);
// EXTERNAL MODULE: ./node_modules/@smithy/smithy-client/dist-es/index.js + 25 modules
var smithy_client_dist_es = __webpack_require__(340);
// EXTERNAL MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/endpoint/EndpointParameters.js
var EndpointParameters = __webpack_require__(19);
// EXTERNAL MODULE: ./node_modules/@aws-sdk/core/dist-es/submodules/protocols/json/parseJsonBody.js + 1 modules
var parseJsonBody = __webpack_require__(902);
// EXTERNAL MODULE: ./node_modules/@smithy/protocol-http/dist-es/index.js + 5 modules
var protocol_http_dist_es = __webpack_require__(479);
;// CONCATENATED MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/models/CognitoIdentityServiceException.js


class CognitoIdentityServiceException extends smithy_client_dist_es/* ServiceException */.TJ {
    constructor(options) {
        super(options);
        Object.setPrototypeOf(this, CognitoIdentityServiceException.prototype);
    }
}

;// CONCATENATED MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/models/models_0.js

const AmbiguousRoleResolutionType = {
    AUTHENTICATED_ROLE: "AuthenticatedRole",
    DENY: "Deny",
};
class InternalErrorException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "InternalErrorException",
            $fault: "server",
            ...opts,
        });
        this.name = "InternalErrorException";
        this.$fault = "server";
        Object.setPrototypeOf(this, InternalErrorException.prototype);
    }
}
class InvalidParameterException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "InvalidParameterException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidParameterException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidParameterException.prototype);
    }
}
class LimitExceededException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "LimitExceededException",
            $fault: "client",
            ...opts,
        });
        this.name = "LimitExceededException";
        this.$fault = "client";
        Object.setPrototypeOf(this, LimitExceededException.prototype);
    }
}
class NotAuthorizedException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "NotAuthorizedException",
            $fault: "client",
            ...opts,
        });
        this.name = "NotAuthorizedException";
        this.$fault = "client";
        Object.setPrototypeOf(this, NotAuthorizedException.prototype);
    }
}
class ResourceConflictException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "ResourceConflictException",
            $fault: "client",
            ...opts,
        });
        this.name = "ResourceConflictException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ResourceConflictException.prototype);
    }
}
class TooManyRequestsException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "TooManyRequestsException",
            $fault: "client",
            ...opts,
        });
        this.name = "TooManyRequestsException";
        this.$fault = "client";
        Object.setPrototypeOf(this, TooManyRequestsException.prototype);
    }
}
const ErrorCode = {
    ACCESS_DENIED: "AccessDenied",
    INTERNAL_SERVER_ERROR: "InternalServerError",
};
class ResourceNotFoundException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "ResourceNotFoundException",
            $fault: "client",
            ...opts,
        });
        this.name = "ResourceNotFoundException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ResourceNotFoundException.prototype);
    }
}
class ExternalServiceException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "ExternalServiceException",
            $fault: "client",
            ...opts,
        });
        this.name = "ExternalServiceException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ExternalServiceException.prototype);
    }
}
class InvalidIdentityPoolConfigurationException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "InvalidIdentityPoolConfigurationException",
            $fault: "client",
            ...opts,
        });
        this.name = "InvalidIdentityPoolConfigurationException";
        this.$fault = "client";
        Object.setPrototypeOf(this, InvalidIdentityPoolConfigurationException.prototype);
    }
}
const MappingRuleMatchType = {
    CONTAINS: "Contains",
    EQUALS: "Equals",
    NOT_EQUAL: "NotEqual",
    STARTS_WITH: "StartsWith",
};
const RoleMappingType = {
    RULES: "Rules",
    TOKEN: "Token",
};
class DeveloperUserAlreadyRegisteredException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "DeveloperUserAlreadyRegisteredException",
            $fault: "client",
            ...opts,
        });
        this.name = "DeveloperUserAlreadyRegisteredException";
        this.$fault = "client";
        Object.setPrototypeOf(this, DeveloperUserAlreadyRegisteredException.prototype);
    }
}
class ConcurrentModificationException extends CognitoIdentityServiceException {
    constructor(opts) {
        super({
            name: "ConcurrentModificationException",
            $fault: "client",
            ...opts,
        });
        this.name = "ConcurrentModificationException";
        this.$fault = "client";
        Object.setPrototypeOf(this, ConcurrentModificationException.prototype);
    }
}

;// CONCATENATED MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/protocols/Aws_json1_1.js





const se_CreateIdentityPoolCommand = async (input, context) => {
    const headers = sharedHeaders("CreateIdentityPool");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_DeleteIdentitiesCommand = async (input, context) => {
    const headers = sharedHeaders("DeleteIdentities");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_DeleteIdentityPoolCommand = async (input, context) => {
    const headers = sharedHeaders("DeleteIdentityPool");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_DescribeIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("DescribeIdentity");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_DescribeIdentityPoolCommand = async (input, context) => {
    const headers = sharedHeaders("DescribeIdentityPool");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetCredentialsForIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("GetCredentialsForIdentity");
    let body;
    body = JSON.stringify((0,smithy_client_dist_es/* _json */.Ss)(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetIdCommand = async (input, context) => {
    const headers = sharedHeaders("GetId");
    let body;
    body = JSON.stringify((0,smithy_client_dist_es/* _json */.Ss)(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetIdentityPoolRolesCommand = async (input, context) => {
    const headers = sharedHeaders("GetIdentityPoolRoles");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetOpenIdTokenCommand = async (input, context) => {
    const headers = sharedHeaders("GetOpenIdToken");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetOpenIdTokenForDeveloperIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("GetOpenIdTokenForDeveloperIdentity");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_GetPrincipalTagAttributeMapCommand = async (input, context) => {
    const headers = sharedHeaders("GetPrincipalTagAttributeMap");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_ListIdentitiesCommand = async (input, context) => {
    const headers = sharedHeaders("ListIdentities");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_ListIdentityPoolsCommand = async (input, context) => {
    const headers = sharedHeaders("ListIdentityPools");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_ListTagsForResourceCommand = async (input, context) => {
    const headers = sharedHeaders("ListTagsForResource");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_LookupDeveloperIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("LookupDeveloperIdentity");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_MergeDeveloperIdentitiesCommand = async (input, context) => {
    const headers = sharedHeaders("MergeDeveloperIdentities");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_SetIdentityPoolRolesCommand = async (input, context) => {
    const headers = sharedHeaders("SetIdentityPoolRoles");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_SetPrincipalTagAttributeMapCommand = async (input, context) => {
    const headers = sharedHeaders("SetPrincipalTagAttributeMap");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_TagResourceCommand = async (input, context) => {
    const headers = sharedHeaders("TagResource");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_UnlinkDeveloperIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("UnlinkDeveloperIdentity");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_UnlinkIdentityCommand = async (input, context) => {
    const headers = sharedHeaders("UnlinkIdentity");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_UntagResourceCommand = async (input, context) => {
    const headers = sharedHeaders("UntagResource");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const se_UpdateIdentityPoolCommand = async (input, context) => {
    const headers = sharedHeaders("UpdateIdentityPool");
    let body;
    body = JSON.stringify(_json(input));
    return buildHttpRpcRequest(context, headers, "/", undefined, body);
};
const de_CreateIdentityPoolCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_DeleteIdentitiesCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_DeleteIdentityPoolCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    await collectBody(output.body, context);
    const response = {
        $metadata: deserializeMetadata(output),
    };
    return response;
};
const de_DescribeIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = de_IdentityDescription(data, context);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_DescribeIdentityPoolCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetCredentialsForIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await (0,parseJsonBody/* parseJsonBody */.Y2)(output.body, context);
    let contents = {};
    contents = de_GetCredentialsForIdentityResponse(data, context);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetIdCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await (0,parseJsonBody/* parseJsonBody */.Y2)(output.body, context);
    let contents = {};
    contents = (0,smithy_client_dist_es/* _json */.Ss)(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetIdentityPoolRolesCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetOpenIdTokenCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetOpenIdTokenForDeveloperIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_GetPrincipalTagAttributeMapCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_ListIdentitiesCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = de_ListIdentitiesResponse(data, context);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_ListIdentityPoolsCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_ListTagsForResourceCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_LookupDeveloperIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_MergeDeveloperIdentitiesCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_SetIdentityPoolRolesCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    await collectBody(output.body, context);
    const response = {
        $metadata: deserializeMetadata(output),
    };
    return response;
};
const de_SetPrincipalTagAttributeMapCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_TagResourceCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_UnlinkDeveloperIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    await collectBody(output.body, context);
    const response = {
        $metadata: deserializeMetadata(output),
    };
    return response;
};
const de_UnlinkIdentityCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    await collectBody(output.body, context);
    const response = {
        $metadata: deserializeMetadata(output),
    };
    return response;
};
const de_UntagResourceCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_UpdateIdentityPoolCommand = async (output, context) => {
    if (output.statusCode >= 300) {
        return de_CommandError(output, context);
    }
    const data = await parseBody(output.body, context);
    let contents = {};
    contents = _json(data);
    const response = {
        $metadata: deserializeMetadata(output),
        ...contents,
    };
    return response;
};
const de_CommandError = async (output, context) => {
    const parsedOutput = {
        ...output,
        body: await (0,parseJsonBody/* parseJsonErrorBody */.CG)(output.body, context),
    };
    const errorCode = (0,parseJsonBody/* loadRestJsonErrorCode */.cJ)(output, parsedOutput.body);
    switch (errorCode) {
        case "InternalErrorException":
        case "com.amazonaws.cognitoidentity#InternalErrorException":
            throw await de_InternalErrorExceptionRes(parsedOutput, context);
        case "InvalidParameterException":
        case "com.amazonaws.cognitoidentity#InvalidParameterException":
            throw await de_InvalidParameterExceptionRes(parsedOutput, context);
        case "LimitExceededException":
        case "com.amazonaws.cognitoidentity#LimitExceededException":
            throw await de_LimitExceededExceptionRes(parsedOutput, context);
        case "NotAuthorizedException":
        case "com.amazonaws.cognitoidentity#NotAuthorizedException":
            throw await de_NotAuthorizedExceptionRes(parsedOutput, context);
        case "ResourceConflictException":
        case "com.amazonaws.cognitoidentity#ResourceConflictException":
            throw await de_ResourceConflictExceptionRes(parsedOutput, context);
        case "TooManyRequestsException":
        case "com.amazonaws.cognitoidentity#TooManyRequestsException":
            throw await de_TooManyRequestsExceptionRes(parsedOutput, context);
        case "ResourceNotFoundException":
        case "com.amazonaws.cognitoidentity#ResourceNotFoundException":
            throw await de_ResourceNotFoundExceptionRes(parsedOutput, context);
        case "ExternalServiceException":
        case "com.amazonaws.cognitoidentity#ExternalServiceException":
            throw await de_ExternalServiceExceptionRes(parsedOutput, context);
        case "InvalidIdentityPoolConfigurationException":
        case "com.amazonaws.cognitoidentity#InvalidIdentityPoolConfigurationException":
            throw await de_InvalidIdentityPoolConfigurationExceptionRes(parsedOutput, context);
        case "DeveloperUserAlreadyRegisteredException":
        case "com.amazonaws.cognitoidentity#DeveloperUserAlreadyRegisteredException":
            throw await de_DeveloperUserAlreadyRegisteredExceptionRes(parsedOutput, context);
        case "ConcurrentModificationException":
        case "com.amazonaws.cognitoidentity#ConcurrentModificationException":
            throw await de_ConcurrentModificationExceptionRes(parsedOutput, context);
        default:
            const parsedBody = parsedOutput.body;
            return throwDefaultError({
                output,
                parsedBody,
                errorCode,
            });
    }
};
const de_ConcurrentModificationExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new ConcurrentModificationException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_DeveloperUserAlreadyRegisteredExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new DeveloperUserAlreadyRegisteredException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_ExternalServiceExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new ExternalServiceException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_InternalErrorExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new InternalErrorException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_InvalidIdentityPoolConfigurationExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new InvalidIdentityPoolConfigurationException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_InvalidParameterExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new InvalidParameterException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_LimitExceededExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new LimitExceededException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_NotAuthorizedExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new NotAuthorizedException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_ResourceConflictExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new ResourceConflictException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_ResourceNotFoundExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new ResourceNotFoundException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_TooManyRequestsExceptionRes = async (parsedOutput, context) => {
    const body = parsedOutput.body;
    const deserialized = (0,smithy_client_dist_es/* _json */.Ss)(body);
    const exception = new TooManyRequestsException({
        $metadata: deserializeMetadata(parsedOutput),
        ...deserialized,
    });
    return (0,smithy_client_dist_es/* decorateServiceException */.Mw)(exception, body);
};
const de_Credentials = (output, context) => {
    return (0,smithy_client_dist_es/* take */.s)(output, {
        AccessKeyId: smithy_client_dist_es/* expectString */.lK,
        Expiration: (_) => (0,smithy_client_dist_es/* expectNonNull */.Y0)((0,smithy_client_dist_es/* parseEpochTimestamp */.l3)((0,smithy_client_dist_es/* expectNumber */.r$)(_))),
        SecretKey: smithy_client_dist_es/* expectString */.lK,
        SessionToken: smithy_client_dist_es/* expectString */.lK,
    });
};
const de_GetCredentialsForIdentityResponse = (output, context) => {
    return (0,smithy_client_dist_es/* take */.s)(output, {
        Credentials: (_) => de_Credentials(_, context),
        IdentityId: smithy_client_dist_es/* expectString */.lK,
    });
};
const de_IdentitiesList = (output, context) => {
    const retVal = (output || [])
        .filter((e) => e != null)
        .map((entry) => {
        return de_IdentityDescription(entry, context);
    });
    return retVal;
};
const de_IdentityDescription = (output, context) => {
    return take(output, {
        CreationDate: (_) => __expectNonNull(__parseEpochTimestamp(__expectNumber(_))),
        IdentityId: __expectString,
        LastModifiedDate: (_) => __expectNonNull(__parseEpochTimestamp(__expectNumber(_))),
        Logins: _json,
    });
};
const de_ListIdentitiesResponse = (output, context) => {
    return take(output, {
        Identities: (_) => de_IdentitiesList(_, context),
        IdentityPoolId: __expectString,
        NextToken: __expectString,
    });
};
const deserializeMetadata = (output) => ({
    httpStatusCode: output.statusCode,
    requestId: output.headers["x-amzn-requestid"] ?? output.headers["x-amzn-request-id"] ?? output.headers["x-amz-request-id"],
    extendedRequestId: output.headers["x-amz-id-2"],
    cfId: output.headers["x-amz-cf-id"],
});
const collectBodyString = (streamBody, context) => collectBody(streamBody, context).then((body) => context.utf8Encoder(body));
const throwDefaultError = (0,smithy_client_dist_es/* withBaseException */.jr)(CognitoIdentityServiceException);
const buildHttpRpcRequest = async (context, headers, path, resolvedHostname, body) => {
    const { hostname, protocol = "https", port, path: basePath } = await context.endpoint();
    const contents = {
        protocol,
        hostname,
        port,
        method: "POST",
        path: basePath.endsWith("/") ? basePath.slice(0, -1) + path : basePath + path,
        headers,
    };
    if (resolvedHostname !== undefined) {
        contents.hostname = resolvedHostname;
    }
    if (body !== undefined) {
        contents.body = body;
    }
    return new protocol_http_dist_es/* HttpRequest */.Kd(contents);
};
function sharedHeaders(operation) {
    return {
        "content-type": "application/x-amz-json-1.1",
        "x-amz-target": `AWSCognitoIdentityService.${operation}`,
    };
}

;// CONCATENATED MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/commands/GetCredentialsForIdentityCommand.js






class GetCredentialsForIdentityCommand extends smithy_client_dist_es/* Command */.uB
    .classBuilder()
    .ep({
    ...EndpointParameters/* commonParams */.S,
})
    .m(function (Command, cs, config, o) {
    return [
        (0,middleware_serde_dist_es/* getSerdePlugin */.TM)(config, this.serialize, this.deserialize),
        (0,dist_es/* getEndpointPlugin */.rD)(config, Command.getEndpointParameterInstructions()),
    ];
})
    .s("AWSCognitoIdentityService", "GetCredentialsForIdentity", {})
    .n("CognitoIdentityClient", "GetCredentialsForIdentityCommand")
    .f(void 0, void 0)
    .ser(se_GetCredentialsForIdentityCommand)
    .de(de_GetCredentialsForIdentityCommand)
    .build() {
}

;// CONCATENATED MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/commands/GetIdCommand.js






class GetIdCommand extends smithy_client_dist_es/* Command */.uB
    .classBuilder()
    .ep({
    ...EndpointParameters/* commonParams */.S,
})
    .m(function (Command, cs, config, o) {
    return [
        (0,middleware_serde_dist_es/* getSerdePlugin */.TM)(config, this.serialize, this.deserialize),
        (0,dist_es/* getEndpointPlugin */.rD)(config, Command.getEndpointParameterInstructions()),
    ];
})
    .s("AWSCognitoIdentityService", "GetId", {})
    .n("CognitoIdentityClient", "GetIdCommand")
    .f(void 0, void 0)
    .ser(se_GetIdCommand)
    .de(de_GetIdCommand)
    .build() {
}

// EXTERNAL MODULE: ./node_modules/@aws-sdk/client-cognito-identity/dist-es/CognitoIdentityClient.js + 8 modules
var CognitoIdentityClient = __webpack_require__(636);
;// CONCATENATED MODULE: ./node_modules/@aws-sdk/credential-provider-cognito-identity/dist-es/loadCognitoIdentity.js




/***/ })

}]);