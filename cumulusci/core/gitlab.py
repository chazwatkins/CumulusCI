from gitlab import Gitlab, GitlabAuthenticationError

from cumulusci.core.config.project_config import BaseProjectConfig
from cumulusci.core.exceptions import GitProviderException, ServiceNotConfigured

from cumulusci.oauth.client import (
    OAuth2ClientConfig,
    OAuth2DeviceConfig,
    get_device_code,
    get_device_oauth_token,
)


HOSTED_SERVER_DOMAIN = "https://gitlab.com"


class GitLabOAuth2ClientConfig(OAuth2ClientConfig):
    response_type: str = "code"

    def __init__(self, server_domain: str = None):
        super(self)

        if server_domain == None:
            server_domain = HOSTED_SERVER_DOMAIN

        self.client_id = ""
        self.auth_uri = f"https://{server_domain}/oauth/authorize"
        self.token_url = f"https://{server_domain}/oauth/token"
        self.scope = "api write_repository"


def get_oauth_device_flow_token():
    """Interactive gitlab authorization"""

    # Get server_domain

    config = GitLabOAuth2ClientConfig()
    device_code = OAuth2DeviceConfig(**get_device_code(config))

    console = Console()
    console.print(
        f"[bold] Enter this one-time code: [red]{device_code.user_code}[/red][/bold]"
    )

    console.print(f"Opening {device_code.verification_uri} in your default browser...")
    webbrowser.open(device_code.verification_uri)
    time.sleep(2)  # Give the user a second or two before we start polling

    with console.status("Polling server for authorization..."):
        device_token: dict = get_device_oauth_token(
            client_config=config, device_config=device_code
        )

    access_token = device_token.get("access_token")
    if access_token:
        console.print(
            f"[bold green]Successfully authorized OAuth token ({access_token[:7]}...)[/bold green]"
        )

    return access_token


def get_auth_from_service(server_domain: str, keychain) -> str:
    servicesByDomain = {
        service.server_domain: service
        for service in keychain.get_services_for_type("gitlab")
    }

    if server_domain not in servicesByDomain.keys():
        raise ServiceNotConfigured(
            f"No GitLab service configured for domain {server_domain}."
        )

    return servicesByDomain.get(server_domain).token


def validate_service(options: dict, keychain) -> dict:
    username = options["username"]
    token = options["token"]
    server_domain = options.get("server_domain", HOSTED_SERVER_DOMAIN)

    services = keychain.get_services_for_type("gitlab")
    existing_self_hosted_services = [
        service.server_domain
        for service in services
        if service.server_domain != HOSTED_SERVER_DOMAIN
        and service.server_domain == server_domain
    ]

    if existing_self_hosted_services != []:
        raise GitProviderException(
            f"More than one GitLab service configured for domain {server_domain}."
        )

    gitlab = Gitlab(url=server_domain)
    if token != None:
        gitlab.private_token = token
    else:
        gitlab.oauth_token = get_auth_from_service(server_domain, keychain)

    try:
        gitlab.auth()
        assert username == gitlab.user.username, f"{username}, {gitlab.user.username}"

    except AssertionError as e:
        raise GitProviderException(
            f"Service username and token username do not match. ({str(e)})"
        )
