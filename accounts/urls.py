from django.urls import path
from .views import AuthorizeView, CallbackView, GenerateTokenView, GetPersonDataView

urlpatterns = [
    path("authorize/", AuthorizeView.as_view(), name="authorize"),
    path("callback/", CallbackView.as_view(), name="callback"),
    path("generate-token/", GenerateTokenView.as_view(), name="generate_token"),
    path("get-person-data/", GetPersonDataView.as_view(), name="get_person_data")

]