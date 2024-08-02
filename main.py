import base64
import json
import logging
import os
import sys

import boto3
import docker
from botocore.exceptions import ClientError
from docker.errors import APIError, TLSParameterError
from kubernetes import client, config
from kubernetes.client import ApiException, CoreV1Api, V1Secret
from requests import HTTPError
from tenacity import retry, stop_after_delay, wait_fixed


def update_docker_credentials_secret(
    k8s_core_client: CoreV1Api,
    namespace: str,
    secret_name: str,
    old_secret: V1Secret,
    registry: str,
    username: str,
    password: str,
    email: str = "",
) -> V1Secret:
    """
    Patches existing docker secret
    """
    docker_config = _get_docker_secret_encoded_string(
        registry, email, username, password
    )
    old_secret.data = {".dockerconfigjson": docker_config}
    try:
        result = k8s_core_client.patch_namespaced_secret(
            secret_name, namespace, body=old_secret
        )
        logging.info(
            f"secret {secret_name} successfully updated in namespace {namespace}"
        )
        return result
    except (ApiException, HTTPError) as exc:
        logging.error(
            f"Failed to patch secret {secret_name} in {namespace} namespace: {exc}"
        )


def create_docker_credentials_secret(
    k8s_core_client: CoreV1Api,
    namespace: str,
    secret_name: str,
    registry: str,
    username: str,
    password: str,
    email: str = "",
) -> V1Secret:
    """
    Creates a docker secret in the namespace
    """
    docker_config = _get_docker_secret_encoded_string(
        registry, email, username, password
    )

    try:
        result = k8s_core_client.create_namespaced_secret(
            namespace=namespace,
            body=client.V1Secret(
                metadata=client.V1ObjectMeta(
                    name=secret_name,
                ),
                type="kubernetes.io/dockerconfigjson",
                data={".dockerconfigjson": docker_config},
            ),
        )
        logging.info(
            f"secret {secret_name} successfully created in namespace {namespace}"
        )
        return result
    except (ApiException, HTTPError) as exc:
        logging.error(
            f"Failed to create a secret {secret_name} in {namespace} namespace: {exc}"
        )


def _get_docker_secret_encoded_string(
    registry: str, email: str, username: str, password: str
) -> str:
    """
    Returns base64 encoded secret string, that is ready to be used as a value for '.dockerconfigjson'
    """
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("utf-8")
    docker_config_dict = {
        "auths": {
            registry: {
                "username": username,
                "password": password,
                "email": email,
                "auth": auth,
            }
        }
    }
    j = json.dumps(docker_config_dict).encode("utf-8")
    docker_config = base64.b64encode(j).decode("utf-8")
    return docker_config


@retry(stop=stop_after_delay(60*10), wait=wait_fixed(10))
def _docker_login(username: str, password: str, registry: str):
    try:
        client = docker.from_env()
        client.login(username=username, password=password, registry=registry)
    except (APIError, TLSParameterError) as err:
        logging.error(f"Failed to login into ECR: {err}")
        raise err

def login_into_ecr() -> tuple[str, str, str]:
    try:
        sts_client = boto3.client("sts")
        account_id = sts_client.get_caller_identity().get("Account")
        logging.info(f"Successfully logged into AWS account {account_id}")
    except ClientError as error:
        logging.error("Failed to get caller identity", error)
        raise error

    ecr_client = boto3.client("ecr")
    try:
        auth_response = ecr_client.get_authorization_token()
    except ClientError as error:
        logging.error("Failed to get authorization token", error)
        raise error

    auth_token = auth_response["authorizationData"][0]["authorizationToken"].encode()
    username, password = base64.b64decode(auth_token).decode().split(":")
    registry = auth_response["authorizationData"][0]["proxyEndpoint"]

    _docker_login(username, password, registry)
    logging.info(f"Successfully logged into ecr docker registry {registry}")

    return registry, username, password


def main():
    logging.basicConfig(stream=sys.stdout, level=logging.INFO)

    result = None
    try:
        result = login_into_ecr()
    except Exception as e:
        logging.error(f"Failed to login into ECR: {e}")
        exit(1)
    registry, username, password = result

    # load cluster config from ~/.kube/config
    config.load_kube_config()
    required_env_vars = ["NAMESPACE", "SECRET_NAME"]

    for ev in required_env_vars:
        if os.environ.get(ev) is None:
            logging.error(f"Environment variable {ev} haven't been set.")
            exit(1)

    namespace = os.environ.get("NAMESPACE")
    secret_name = os.environ.get("SECRET_NAME")

    v1 = client.CoreV1Api()
    try:
        secret = v1.read_namespaced_secret(secret_name, namespace)

        # secret already exist, the value needs to be updated
        update_docker_credentials_secret(
            v1, namespace, secret_name, secret, registry, username, password
        )
    except (ApiException, HTTPError) as exc:
        if isinstance(exc, ApiException) and exc.status == 404:
            # secret not found
            create_docker_credentials_secret(
                v1, namespace, secret_name, registry, username, password
            )
        else:
            logging.error(
                f"Failed to set secret '{secret_name}' value in '{namespace}' namespace"
            )
            exit(1)


if __name__ == "__main__":
    main()
