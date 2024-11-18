from django.core.signing import TimestampSigner, BadSignature, SignatureExpired

signer = TimestampSigner()

def generate_verification_token(user):
    return signer.sign(user.id)

def verify_token(token, max_age=86400):
    try:
        user_id = signer.unsign(token, max_age=max_age)
        return user_id
    except (BadSignature, SignatureExpired):
        return None
