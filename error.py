# pylint: skip-file
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
    NotAllowed = ['405']
    Unavailable = ['503']
    UnknownProtocol = ['UnknownProtocol']
    MCB = ['MCB']
    Redirect = ['Redirect']
    Other = ['Other']
    Ign = ['Ign']
    ProblematicRef = (
        Reset, Refused, Timeout, UnknownProtocol, InvalidCert,
        BadRequest, Unauthorized, Forbidden, NotFound, NotAllowed, Unavailable,
        MCB, Redirect, Other, Ign
    )

HTTP_ERROR = {
    400: domain.BadRequest,
    401: domain.Unauthorized,
    403: domain.Forbidden,
    404: domain.NotFound,
    405: domain.NotAllowed,
    500: domain.Unavailable,
    502: domain.Unavailable,
    503: domain.Unavailable,
    504: domain.Unavailable
}

URL_ERROR = {
    '[Errno 11001] getaddrinfo failed': domain.DNS,
    '[Errno 11002] getaddrinfo failed': domain.DNS,
    '[WinError 10061] 由于目标计算机积极拒绝，无法连接。': domain.Refused,
    'EOF occurred in violation of protocol (_ssl.c:645)': domain.Reset,
    'timed out': domain.Timeout,
    '[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed (_ssl.c:749)': domain.InvalidCert,
    '[SSL: UNKNOWN_PROTOCOL] unknown protocol (_ssl.c:645)': domain.UnknownProtocol
}
