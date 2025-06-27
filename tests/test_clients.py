from fastapi.testclient import TestClient
from bson import ObjectId
from datetime import timedelta
from jose import jwt, JWTError
import time
import json
from unittest.mock import patch, MagicMock

from app.main import app
from app.models.client import ClientModel
from app.security.auth import create_access_token
from app.services.client_service import (
    create_client, get_client, list_clients, update_client, delete_client
)
# Import des fonctions de publication et de consommation RabbitMQ
from app.messaging.rabbitmq import publish_client_created, consume_client_created

client = TestClient(app)

def get_auth_headers(role="admin"):
    """
    Génère des en-têtes d'authentification avec un token JWT.
    - role: rôle de l'utilisateur (par défaut "admin")
    Retourne un dictionnaire avec l'en-tête Authorization contenant le token JWT.
    """
    token = create_access_token({"sub": "testuser", "role": role})
    return {"Authorization": f"Bearer {token}"}

# ROUTES

def test_create_client():
    """
    Teste la création d'un client via l'API.
    - Envoie une requête POST à /clients/ avec des données de client valides.
    - Vérifie que la réponse a un code 201 Created.
    - Vérifie que les données du client créé correspondent à celles envoyées.
    """
    payload = {
        "name": "Test Client",
        "email": "test@example.com",
        "company": "TestCorp",
        "phone": "+330000000",
        "is_active": True
    }
    response = client.post("/clients/", json=payload, headers=get_auth_headers())
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Test Client"

def test_list_clients():
    response = client.get("/clients/", headers=get_auth_headers())
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_get_single_client():
    payload = {
        "name": "Client X",
        "email": "clientx@example.com"
    }
    create_resp = client.post("/clients/", json=payload, headers=get_auth_headers())
    client_id = create_resp.json()["_id"]

    get_resp = client.get(f"/clients/{client_id}", headers=get_auth_headers())
    assert get_resp.status_code == 200
    assert get_resp.json()["email"] == "clientx@example.com"

def test_update_client():
    payload = {
        "name": "Old Name",
        "email": "update@example.com",
        "company": "OldCorp",
        "phone": "+33123456789",
        "is_active": True
    }
    create_resp = client.post("/clients/", json=payload, headers=get_auth_headers())
    client_id = create_resp.json()["_id"]

    updated = {
        "name": "New Name",
        "email": "update@example.com",
        "company": "NewCorp",
        "phone": "+33999999999",
        "is_active": False
    }
    update_resp = client.put(f"/clients/{client_id}", json=updated, headers=get_auth_headers())
    assert update_resp.status_code == 200
    assert update_resp.json()["name"] == "New Name"

def test_delete_client():
    payload = {"name": "Delete Me", "email": "delete@example.com"}
    create_resp = client.post("/clients/", json=payload, headers=get_auth_headers())
    client_id = create_resp.json()["_id"]

    delete_resp = client.delete(f"/clients/{client_id}", headers=get_auth_headers())
    assert delete_resp.status_code == 204

    get_resp = client.get(f"/clients/{client_id}", headers=get_auth_headers())
    assert get_resp.status_code == 404

def test_unauthorized_access():
    response = client.get("/clients/")
    assert response.status_code == 401

def test_forbidden_role():
    token = create_access_token({"sub": "user", "role": "user"})
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/clients/", headers=headers)
    assert response.status_code == 403

# SERVICES

def test_get_client_direct():
    payload = {
        "name": "FromService",
        "email": "service@example.com",
        "company": "ServCorp",
        "phone": "+33777777777",
        "is_active": True
    }
    resp = client.post("/clients/", json=payload, headers=get_auth_headers())
    client_id = resp.json()["_id"]

    result = get_client(client_id)
    assert result is not None
    assert result.name == "FromService"

def test_get_client_not_found():
    fake_id = str(ObjectId())
    result = get_client(fake_id)
    assert result is None

def test_update_client_not_found():
    fake_id = str(ObjectId())
    updated_data = ClientModel(name="DoesNotExist", email="fake@email.com")
    result = update_client(fake_id, updated_data)
    assert result is None

def test_update_client_invalid_id():
    invalid_id = "not-an-id"
    updated_data = ClientModel(name="DoesNotExist", email="fake@email.com")
    result = update_client(invalid_id, updated_data)
    assert result is None

def test_delete_client_not_found():
    fake_id = str(ObjectId())
    result = delete_client(fake_id)
    assert result is False

def test_delete_client_invalid_id():
    invalid_id = "invalid-id"
    result = delete_client(invalid_id)
    assert result is False

def test_create_client_direct():
    client_data = ClientModel(
        name="Unit Test",
        email="unit@test.com",
        company="UnitCo",
        phone="+33123456789"
    )
    result = create_client(client_data)
    assert isinstance(result, ClientModel)
    assert result.email == "unit@test.com"

# AUTRES

def test_token_expiration():
    short_token = create_access_token(data={"sub": "user"}, expires_delta=timedelta(seconds=1))
    time.sleep(2)
    try:
        jwt.decode(short_token, "changeme", algorithms=["HS256"])
        assert False, "Token should be expired"
    except JWTError:
        pass

def test_token_endpoint_admin():
    response = client.post("/token", data={"username": "admin", "password": "any"})
    assert response.status_code == 200
    token = response.json().get("access_token")
    assert token is not None
    assert isinstance(token, str)

def test_token_endpoint_user():
    """
    Teste la génération d'un token pour un utilisateur non-admin.
    - Envoie une requête POST à /token avec un utilisateur non-admin.
    - Vérifie que la réponse a un code 200 OK.
    - Vérifie que le token est généré et est une chaîne de caractères.
    """
    response = client.post("/token", data={"username": "randomuser", "password": "irrelevant"})
    assert response.status_code == 200
    token = response.json().get("access_token")
    assert token is not None
    assert isinstance(token, str)

def test_update_client_no_change():
    """
    Teste la mise à jour d'un client avec les mêmes données.
    - Envoie une requête PUT à /clients/{client_id} avec les mêmes données.
    - Vérifie que la réponse a un code 200 OK.
    """
    payload = {"name": "SameName", "email": "same@example.com"}
    create_resp = client.post("/clients/", json=payload, headers=get_auth_headers())
    client_id = create_resp.json()["_id"]

    updated_data = {"name": "SameName", "email": "same@example.com"}
    update_resp = client.put(f"/clients/{client_id}", json=updated_data, headers=get_auth_headers())
    assert update_resp.status_code == 200

def test_metrics_route():
    """
    Teste l'accès à la route /metrics.
    - Envoie une requête GET à /metrics.
    - Vérifie que la réponse a un code 200 OK.
    """
    response = client.get("/metrics")
    assert response.status_code == 200

# MESSAGING

def test_publish_client_created():
    '''
    Teste la publication d'un message client_created dans RabbitMQ.
    - Simule la publication d'un message RabbitMQ.
    - Vérifie que le message est publié avec les bonnes données.
    '''
    mock_channel = MagicMock()
    client_data = {"name": "Test", "email": "test@example.com"}

    publish_client_created(client_data, channel=mock_channel)

    mock_channel.basic_publish.assert_called_once()
    args, kwargs = mock_channel.basic_publish.call_args
    assert kwargs["routing_key"] == "client_created"
    assert kwargs["body"] == '{"name": "Test", "email": "test@example.com"}'
    assert kwargs["exchange"] == ""
    assert kwargs["properties"].delivery_mode == 2
    mock_channel.close.assert_called_once()

def test_consume_client_created():
    '''
    Teste la consommation du message client_created.
    - Simule la consommation d'un message RabbitMQ.
    - Vérifie que le callback est appelé avec les données du message.
    '''
    mock_callback = MagicMock()
    mock_channel = MagicMock()

    with patch("app.messaging.rabbitmq.get_channel", return_value=mock_channel):
        consume_client_created(mock_callback)

        mock_channel.basic_consume.assert_called_once()
        mock_channel.start_consuming.assert_called_once()

def test_publish_client_created_with_default_channel():
    mock_channel = MagicMock()
    with patch("app.messaging.rabbitmq.get_channel", return_value=mock_channel):
        client_data = {"name": "AutoChannel", "email": "auto@example.com"}
        publish_client_created(client_data)

        mock_channel.basic_publish.assert_called_once()
        mock_channel.close.assert_called_once()

def test_consume_client_created_callback_wrapper():
    mock_channel = MagicMock()
    mock_callback = MagicMock()
    mock_body = json.dumps({"name": "CallbackTest"}).encode()
    mock_method = MagicMock()
    mock_method.delivery_tag = "abc123"

    with patch("app.messaging.rabbitmq.get_channel", return_value=mock_channel):
        # Extraire la fonction wrapper (car start_consuming est bloquant)
        consume_client_created(mock_callback)
        args, kwargs = mock_channel.basic_consume.call_args
        on_message_callback = kwargs["on_message_callback"]

        # Simuler un appel au wrapper
        on_message_callback(mock_channel, mock_method, None, mock_body)

        mock_callback.assert_called_once_with({"name": "CallbackTest"})
        mock_channel.basic_ack.assert_called_once_with(delivery_tag="abc123")

def test_get_channel_creates_connection():
    '''
    Teste la création d'un canal RabbitMQ.
    - Vérifie que la connexion est établie et le canal créé.
    - Vérifie que la file d'attente 'client_created' est déclarée.
    '''
    with patch("app.messaging.rabbitmq.pika.BlockingConnection") as mock_conn:
        mock_channel = MagicMock()
        mock_conn.return_value.channel.return_value = mock_channel

        from app.messaging.rabbitmq import get_channel
        channel = get_channel()

        mock_conn.assert_called_once()
        mock_channel.queue_declare.assert_called_once_with(queue='client_created', durable=True)
        assert channel == mock_channel

def test_consume_client_created_callback_wrapper():
    from app.messaging.rabbitmq import consume_client_created

    mock_channel = MagicMock()
    mock_callback = MagicMock()
    mock_body = json.dumps({"name": "Test"}).encode()

    with patch("app.messaging.rabbitmq.get_channel", return_value=mock_channel):
        ''' 
        Teste la consommation du message client_created avec un wrapper.
        - Simule la consommation d'un message RabbitMQ.
        - Vérifie que le callback est appelé avec les données du message.
        ''' 
        consume_client_created(mock_callback)

        assert mock_channel.basic_consume.called
        _, kwargs = mock_channel.basic_consume.call_args
        wrapper_func = kwargs["on_message_callback"]

        # Appel manuel de la fonction wrapper
        mock_method = MagicMock()
        mock_method.delivery_tag = "xyz"

        wrapper_func(mock_channel, mock_method, None, mock_body)

        mock_callback.assert_called_once_with({"name": "Test"})
        mock_channel.basic_ack.assert_called_once_with(delivery_tag="xyz")

