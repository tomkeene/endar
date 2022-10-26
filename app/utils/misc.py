from flask import current_app
from itsdangerous import (TimedJSONWebSignatureSerializer as Serializer, BadSignature, SignatureExpired)

def verify_jwt(token):
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired:
        current_app.logger.warning("SignatureExpired while verifying JWT")
        return False
    except BadSignature:
        current_app.logger.warning("BadSignature while verifying JWT")
        return False
    return data

def generate_jwt(self, data={}, expiration = 6000):
    s = Serializer(current_app.config['SECRET_KEY'], expires_in = expiration)
    return s.dumps(data).decode('utf-8')

def bytes2human(n, format="%(value).1f%(symbol)s"):
    """Used by various scripts. See:
    http://goo.gl/zeJZl
    >>> bytes2human(10000)
    '9.8K'
    >>> bytes2human(100001221)
    '95.4M'
    """
    symbols = ('B', 'K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols[1:]):
        prefix[s] = 1 << (i + 1) * 10
    for symbol in reversed(symbols[1:]):
        if n >= prefix[symbol]:
            value = float(n) / prefix[symbol]
            return format % locals()
    return format % dict(symbol=symbols[0], value=n)

def request_to_json(request):
    data = {
        "headers":dict(request.headers),
        "body":request.get_json(silent=True),
        "args":request.args.to_dict(),
    }
    for property in ["origin","method","mimetype","referrer","remote_addr","url"]:
        data[property] = getattr(request,property)
    return data
