from datetime import datetime, timedelta

# REPLACE THIS WITH YOUR USER INSTANCE
from app.models import User
from jose import jwt, JWTError
from jose.constants import ALGORITHMS


class JWTokenService:

    # This is our own app secret for signing the payloads
    TOKEN_SECRET = 'SECRET_HERE'
    TOKEN_EXP_DELAY_DELTA_DAYS = datetime.utcnow() + timedelta(days=1)
    TOKEN_EXP_TIME = TOKEN_EXP_DELAY_DELTA_DAYS

    @staticmethod
    def _increment_token_version(user_id, user_token_version):
        # TODO limit the maximum possible value for the version number

        # Retreive user object
        try:
            user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            raise JWTError("user_id[%s] provided does not exist in database")
        # Increment hex version by 1
        try:
            new_token_version = hex(int(user_token_version, base=16) + 1)
        except ValueError:
            raise JWTError("Current token: %s is not a valid hex value")
        # Save token version
        user.jwt_token_version = new_token_version
        user.save()

    # Used @classmethod instead of @staticmethod since
    # functions accesses class variables TOKEN_SECRET

    @classmethod
    def create_token(cls, user_id, user_token_version):
        # Class method should be called once user instance has been
        # created and authenticated with FB's access token stored in DB

        # Define payload to include in the token and also to
        # identify the user using his/her ID
        payload = {
            'user_id': user_id,
            'version': user_token_version,
            'exp': datetime.utcnow() + timedelta(days=cls.TOKEN_EXP_TIME)
        }

        # Sign our paylod using HS512 algorithm from the python-jose library
        token = jwt.encode(payload, cls.TOKEN_SECRET, ALGORITHMS.HS512)

        # If token was succesfully encoded, increment the token version
        # So that only one device at a time is supposedly logged in
        cls._increment_token_version(user_id, user_token_version)

        # Return the token
        return token

    @classmethod
    def verify_token(cls, jwt_token):
        # Decode the token
        jwt_payload = jwt.decode(jwt_token, cls.TOKEN_SECRET, ALGORITHMS.HS512)
        # Load the necessary user parameters
        try:
            user_id = jwt_payload['user_id']
            token_version = jwt_payload['version']
        except KeyError as e:
            raise JWTError("Key not found. Invalidating! %s" % e)

        # The version of the token must match the current version saved
        # on the DB. If not, this is an old request or the request has
        # been tampered with. Increment if invalid
        try:
            user_token_version = User.objects.get(id=user_id).jwt_token_version
        except User.DoesNotExist:
            raise JWTError("user_id[%s] provided does not exist in database")
        if user_token_version != token_version:
            raise JWTError(
                "Invalid Version! DB: %s, JWT: %s" % user_token_version,
                token_version
            )

        # Token is all good, pass the payload back
        return jwt_payload


