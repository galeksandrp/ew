class domain:
    OK = []
    DNS = ['DNS']
    Reset = ['Reset']
    Refused = ['Refused']
    Timeout = ['Timeout']
    InvalidCert = ['Invalid Certificate']
    BadRequest = ['400']
    Unauthorized = ['401']
    Forbidden = ['403']
    NotFound = ['404']
    Unavailable = ['503']
    UnknownProtocol = ['UnknownProtocol']
    MCB = ['MCB']
    Redirect = ['Redirect']
    Other = ['Other']
    Ign = ['Ign']
    ProblematicRef = (
        Reset, Refused, Timeout, UnknownProtocol, InvalidCert,
        BadRequest, Unauthorized, Forbidden, NotFound, Unavailable,
        MCB, Redirect, Other, Ign
    )

httpError = {
    400: domain.BadRequest,
    401: domain.Unauthorized,
    403: domain.Forbidden,
    404: domain.NotFound,
    500: domain.Unavailable,
    503: domain.Unavailable
}
