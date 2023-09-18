import jwt

from django.conf import settings
from django.contrib.auth.models import User  # lint-amnesty, pylint: disable=imported-auth-user
from jwt import PyJWKClient

class Auth0Backend:
    """
    A Django authentication backend that authenticates users via Auth0. This
    backend will only return a User object if the Auth0 ID Token is valid.
    """

    def authenticate(self, _request, username=None, id_token=None):
        """
        Try to authenticate a user. This method will return a Django user object
        if a user with the corresponding username exists in the database, and
        if the username in the ID Token matches.

        If such a user is not found, the method returns None (in line with the
        authentication backend specification).
        """
        if not id_token:
            return None

        try:
            edx_user = User.objects.get(username=username)
        except User.DoesNotExist:
            return None

        try:
            jwks_client = PyJWKClient(f"https://{getattr(settings, 'AUTH0_DOMAIN')}/.well-known/jwks.json")
            signing_key = jwks_client.get_signing_key_from_jwt(id_token)
            data = jwt.decode(id_token, signing_key.key, algorithms=["RS256"], audience=getattr(settings, 'AUTH0_CLIENT_ID'))
            print(data)
        except Exception as err:
            print('backend')
            print(err)
            return None

        return edx_user

    def get_user(self, user_id):
        """
        Return the User object for a user that has already been authenticated by
        this backend.
        """
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
