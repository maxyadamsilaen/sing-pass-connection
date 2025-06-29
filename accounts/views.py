from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from core_abnk.client import MyInfoPersonalClientV4
from core_abnk.security import generate_ephemeral_session_keypair, decrypt_jwe


import uuid
import requests

session_ephemeral_keypair = generate_ephemeral_session_keypair()
oauth_state = str(uuid.uuid4())  # Generate a unique state for security


class AuthorizeView(APIView):
    """
    API endpoint to generate MyInfo authorization URL.
    """

    def get(self, request):
        callback_url = request.query_params.get("callback_url")

        if not callback_url:
            return Response({"error": "callback_url is required"}, status=status.HTTP_400_BAD_REQUEST)

        authorize_url = MyInfoPersonalClientV4.get_authorise_url(oauth_state, callback_url)

        return Response({"authorize_url": authorize_url}, status=status.HTTP_200_OK)


class CallbackView(APIView):
    """
    API endpoint to handle the callback from SingPass and retrieve the authorization code.
    """

    def get(self, request):
        auth_code = request.query_params.get("code")

        if not auth_code:
            return Response({"error": "Authorization code is missing"}, status=status.HTTP_400_BAD_REQUEST)

        return Response({"message": "Authorization code received", "code": auth_code}, status=status.HTTP_200_OK)


class GenerateTokenView(APIView):
    """
    API endpoint to generate access token using authorization code.
    """

    def post(self, request):
        auth_code = request.data.get("code")
        callback_url = request.data.get("callback_url")

        access_token_resp = MyInfoPersonalClientV4().get_access_token(
            auth_code=auth_code,
            state=oauth_state,
            callback_url=callback_url,
            session_ephemeral_keypair=session_ephemeral_keypair,
        )

        return Response(access_token_resp, status=status.HTTP_200_OK)

class GetPersonDataView(APIView):
    """
    API endpoint to retrieve personal data from MyInfo using an access token.
    """

    def get(self, request):
        access_token = request.headers.get("Authorization")

        if not access_token:
            return Response({"error": "Access token is required"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            if access_token.startswith("DPoP "):
                access_token = access_token.split(" ")[1]

            myinfo_client = MyInfoPersonalClientV4()
            encrypted_response = myinfo_client.get_person_data(access_token, session_ephemeral_keypair)

            decrypted_data = decrypt_jwe(encrypted_response)

            return Response(decrypted_data, status=status.HTTP_200_OK)

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)