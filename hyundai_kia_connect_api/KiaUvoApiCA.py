"""KiaUvoApiCA.py"""

import base64
import datetime as dt
import json
import logging
import platform
import ssl
import time
import uuid
from typing import Any, cast
from zoneinfo import ZoneInfo

import certifi
import requests
from requests.adapters import DEFAULT_POOLBLOCK, DEFAULT_POOLSIZE, HTTPAdapter
from urllib3.connection import HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.poolmanager import PoolManager, ProxyManager
from urllib3.util.ssl_ import create_urllib3_context

# Try to fix hyundai/cloudflare
from .ApiImpl import (
    ApiImpl,
    ApiImplSession,
    ClimateRequestOptions,
    OTPRequest,
    ScheduleChargingClimateRequestOptions,
    _fill_schedule_options_from_vehicle,
    _schedule_charging_scopes,
)
from .const import (
    BRAND_GENESIS,
    BRAND_HYUNDAI,
    BRAND_KIA,
    BRANDS,
    DISTANCE_UNITS,
    DOMAIN,
    ENGINE_TYPES,
    ORDER_STATUS,
    OTP_NOTIFY_TYPE,
    SEAT_STATUS,
    TEMPERATURE_UNITS,
    VALET_MODE_ACTION,
    VEHICLE_LOCK_ACTION,
)
from .exceptions import (
    APIError,
    AuthenticationBlockedError,
    AuthenticationError,
    AuthenticationInvalidCredentialsError,
    AuthenticationTokenExpiredError,
    InvalidAPIResponseError,
    UnsupportedControlError,
)
from .Token import Token
from .utils import (
    detect_timezone_for_date,
    get_child_value,
    get_hex_temp_into_index,
    get_index_into_hex_temp,
    int_or_none,
    normalize_battery_soc,
    offset_from_tz,
    parse_datetime,
)
from .Vehicle import DailyDrivingStats, Vehicle

_LOGGER = logging.getLogger(__name__)


CA_TIMEZONES = [
    ZoneInfo(f"Canada/{zone}")
    for zone in [
        "Newfoundland",
        "Atlantic",
        "Eastern",
        "Central",
        "Mountain",
        "Pacific",
    ]
]


def _reservation_time(value: Any) -> dt.time | None:
    """{"time": "%I%M", "timeSection": 0 am / 1 pm}; "0000" is the never-set value."""
    raw = str(get_child_value(value, "time") or "")
    if len(raw) != 4 or not raw.isdigit() or raw == "0000":
        return None
    hour, minute = int(raw[:2]), int(raw[2:])
    if not 1 <= hour <= 12 or minute > 59:
        return None
    pm = get_child_value(value, "timeSection") == 1
    return dt.time(hour % 12 + (12 if pm else 0), minute)


def _reservation_time_body(value: dt.time) -> dict[str, Any]:
    return {
        "time": value.strftime("%I%M"),
        "timeSection": 1 if value >= dt.time(12, 0) else 0,
    }


def _add_steering_wheel_step(
    body: dict[str, Any], options: ClimateRequestOptions
) -> None:
    """Send the heated wheel level the way kiaconnect.ca does.

    Cars with a 2-step wheel (feature StrgWhlHeatingOption 2) take the level as
    steerWheelHeat_step2 (0 off, 1 low, 2 high) and the side/back defrosters as
    a separate sideBackWindowHeat flag. Only added when steering_wheel is set,
    so requests from callers that don't use it are unchanged.
    """
    if options.steering_wheel is None:
        return
    body["steerWheelHeat_step2"] = int(options.steering_wheel)
    body["sideBackWindowHeat"] = 1 if options.heating in (1, 2, 4) else 0


def _ymd_date(value: Any) -> dt.date | None:
    """CA dates are YYYYMMDD strings; anything else is unknown."""
    raw = str(value or "")
    if len(raw) != 8 or not raw.isdigit():
        return None
    try:
        return dt.date(int(raw[:4]), int(raw[4:6]), int(raw[6:]))
    except ValueError:
        return None


# Departure slots in lstvhclsts / getresdetails (slot number, status key, body key)
_CA_DEPARTURE_SLOTS = (
    (1, "reservChargeInfo", "reservedHVACInfo1"),
    (2, "reserveChargeInfo2", "reservedHVACInfo2"),
)
# reservInfo.day holds 0-6 (Sun=0); 9 is the portal's "no day" marker.
_CA_NO_DAY = 9


def create_session_ticket_context() -> ssl.SSLContext:
    """An SSL context with TLS session tickets enabled.

    Cloudflare in front of the CA endpoints fingerprints the TLS ClientHello.
    urllib3 sets OP_NO_TICKET on the contexts it builds by default; with
    Python 3.14 / OpenSSL 3.5 (Home Assistant 2026.10) that ClientHello is
    classified as a bot and v2/login answers 403 with an HTML block page.
    This context keeps tickets enabled and is let through.

    OpenSSL 3.5+ also offers a hybrid post-quantum X25519MLKEM768 key share
    in that ClientHello by default, which Cloudflare scores as a bot even
    with tickets enabled (Hyundai-Kia-Connect/kia_uvo#2119); on
    those builds the key exchange groups are pinned to X25519. Python 3.15
    exposes that as set_groups; 3.14 does the same through set_ecdh_curve,
    which OpenSSL applies to the TLS 1.3 group list as well.
    """
    context = create_urllib3_context()
    context.options &= ~ssl.OP_NO_TICKET
    if ssl.OPENSSL_VERSION_INFO >= (3, 5):
        if hasattr(context, "set_groups"):
            context.set_groups("X25519")
        else:
            context.set_ecdh_curve("X25519")
    return context


class _SessionTicketConnection(HTTPSConnection):
    """An HTTPSConnection that builds its SSL context fresh per connection.

    urllib3 mutates context.verify_mode before every handshake. Environments
    that inject pyOpenSSL >= 26.2 into urllib3 reject mutating a context that
    already created a connection (urllib3 #5107), so a pool-shared context
    fails on the second connection onwards. A fresh context per connection
    sidesteps that in both injected and plain setups.
    """

    def connect(self) -> None:
        self.ssl_context = create_session_ticket_context()
        super().connect()


class _SessionTicketConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _SessionTicketConnection


class _SessionTicketPoolManager(PoolManager):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": HTTPConnectionPool,
            "https": _SessionTicketConnectionPool,
        }


class _SessionTicketProxyManager(ProxyManager):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.pool_classes_by_scheme = {
            "http": HTTPConnectionPool,
            "https": _SessionTicketConnectionPool,
        }


class SessionTicketAdapter(HTTPAdapter):
    """An HTTPAdapter mounting pools whose connections enable TLS session
    tickets (see _SessionTicketConnection for why)."""

    def init_poolmanager(
        self,
        connections: int = DEFAULT_POOLSIZE,
        maxsize: int = DEFAULT_POOLSIZE,
        block: bool = DEFAULT_POOLBLOCK,
        **kwargs: Any,
    ) -> None:
        kwargs["ca_certs"] = certifi.where()
        self.poolmanager = _SessionTicketPoolManager(
            num_pools=connections,
            maxsize=maxsize,
            block=block,
            **kwargs,
        )

    def proxy_manager_for(self, proxy: str, **kwargs: Any) -> Any:
        if proxy in self.proxy_manager:
            return self.proxy_manager[proxy]
        if proxy.lower().startswith("socks"):
            return super().proxy_manager_for(proxy, **kwargs)
        manager = self.proxy_manager[proxy] = _SessionTicketProxyManager(
            proxy,
            proxy_headers=self.proxy_headers(proxy),
            num_pools=DEFAULT_POOLSIZE,
            maxsize=DEFAULT_POOLSIZE,
            block=DEFAULT_POOLBLOCK,
            **kwargs,
        )
        return manager


class RetrySession(ApiImplSession):
    def __init__(self, max_retries: int = 3, delay: int = 2, backoff: int = 2) -> None:
        super().__init__()
        self.mount("https://", SessionTicketAdapter())
        self.max_retries = max_retries
        self.delay = delay
        self.backoff = backoff

    def post(
        self, url: str | bytes, data: Any = None, json: Any = None, **kwargs: Any
    ) -> requests.Response:
        return self._request_with_retry("POST", url, data=data, json=json, **kwargs)

    def _request_with_retry(
        self, method: str, url: str | bytes, **kwargs: Any
    ) -> requests.Response:
        attempt = 0
        current_delay = self.delay

        while attempt < self.max_retries:
            try:
                _LOGGER.debug(f"{DOMAIN} - Try to request {attempt + 1}")
                response = super().request(method, url, **kwargs)

                return response
            except requests.exceptions.ConnectionError as e:
                _LOGGER.debug(
                    f"{DOMAIN} - Attempt {attempt + 1}: Connection error ({e}), retrying..."
                )
                last_exception = e
                time.sleep(current_delay)
                current_delay *= self.backoff
                attempt += 1
            except requests.exceptions.RequestException as e:
                _LOGGER.debug(
                    f"{DOMAIN} - {method} Other exception not connection reset {attempt + 1}: Connection error ({e})"
                )
                raise

        raise last_exception


# EVs whose climate body is remoteControl: they reject hvacInfo with 15109
# (Hyundai-Kia-Connect/kia_uvo#2110). Matched on the model without spaces.
_CA_REMOTE_CONTROL_CLIMATE_MODELS = frozenset({"EV5", "EV9", "IONIQ9"})


_CA_APP_HEADERS: dict[str, str | None] = {
    # App-shaped profile, myHyundai CA 2.0.47 HACCRequestHeader (Hyundai-Kia-Connect/kia_uvo#2054)
    "User-Agent": "okhttp/4.12.0",
    "Accept-Encoding": "gzip, deflate",
    "Content-Type": "application/json;charset=UTF-8",
    "from": "SPA",
    "offset": "-5",
    "language": "0",
    "client_id": "HATAHSPACA0232141ED9722C67715A0B",
    "client_secret": "CLISCR01AHSPA",
}

_CA_PORTAL_HEADERS: dict[str, str | None] = {
    # Web-portal profile, kiaconnect.ca — proven since 3.21; kiaconnect rejects SPA-shaped v2/login (7404)
    "User-Agent": "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-CA,en-US;q=0.8,en;q=0.5,fr;q=0.3",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Content-Type": "application/json;charset=UTF-8",
    "from": "CWP",
    "offset": "-5",
    "language": "0",
    "Connection": "keep-alive",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
    "Priority": "u=0",
    "Pragma": "no-cache",
    "Cache-Control": "no-cache",
    "client_id": "HATAHSPACA0232141ED9722C67715A0B",
    "client_secret": "CLISCR01AHSPA",
}

_CA_APP_HEADERS_G: dict[str, str | None] = {
    # Genesis CA app (stationdm.hca hca/network/repo/net/c.java): SPA, brand G, own client keys
    "brand": "G",
    "client_id": "HATAGSPACA0232141ED9722C67715A0B",
    "client_secret": "CLISCR01AGSPA",
}


class KiaUvoApiCA(ApiImpl):
    """KiaUvoApiCA"""

    temperature_range_c_old = tuple(x * 0.5 for x in range(32, 64))
    temperature_range_c_new = tuple(x * 0.5 for x in range(28, 64))
    temperature_range_model_year = 2020

    def __init__(self, region: int, brand: int, language: str) -> None:
        self.LANGUAGE: str = language
        self.brand = brand
        if BRANDS[brand] == BRAND_KIA:
            self.BASE_URL: str = "kiaconnect.ca"
        elif BRANDS[brand] == BRAND_HYUNDAI:
            self.BASE_URL = "mybluelink.ca"
        elif BRANDS[brand] == BRAND_GENESIS:
            self.BASE_URL = "genesisconnect.ca"

        self.API_URL: str = "https://" + self.BASE_URL + "/tods/api/"
        self._sessions: RetrySession | None = None
        # Cached device_id. Seeded from the persisted Token by refresh_access_token
        # (so re-login reuses it), or computed once from MAC+hostname on first login.
        self._device_id: str | None = None
        # G3 EVs that rejected the remoteControl climate body and accepted hvacInfo.
        self._hvac_info_climate_ids: set[str] = set()

    @property
    def API_HEADERS(self) -> dict[str, str | None]:
        """App profile per brand with a fresh offset (Hyundai-Kia-Connect/kia_uvo#2054); Kia keeps the proven web-portal shape."""
        if BRANDS[self.brand] == BRAND_GENESIS:
            headers = dict(_CA_APP_HEADERS)
            headers.update(_CA_APP_HEADERS_G)
            headers["offset"] = offset_from_tz()
            return headers
        if BRANDS[self.brand] != BRAND_HYUNDAI:
            headers = dict(_CA_PORTAL_HEADERS)
            headers["Origin"] = f"https://{self.BASE_URL}"
            headers["Referer"] = f"https://{self.BASE_URL}/login"
            return headers
        headers = dict(_CA_APP_HEADERS)
        headers["offset"] = offset_from_tz()
        return headers

    def _get_device_id(self) -> str:
        """Return a stable device ID, persisted across re-logins.

        Reuse the cached device_id if set (seeded from the persisted Token by
        refresh_access_token, or computed on first login). Otherwise derive it
        deterministically from MAC+hostname (uuid5) and cache it. Caching means
        a Docker restart with a changed MAC/hostname no longer produces a new
        device_id the server does not recognize (Hyundai-Kia-Connect/kia_uvo#1715).
        """
        if self._device_id is None:
            device_uuid = uuid.uuid5(
                uuid.NAMESPACE_DNS, f"{uuid.getnode():x}-{platform.node() or ''}"
            )
            self._device_id = base64.b64encode(device_uuid.hex.encode()).decode()
        return self._device_id

    @property
    def sessions(self) -> RetrySession:
        if not self._sessions:
            self._sessions = RetrySession(max_retries=4, delay=2, backoff=2)
        return self._sessions

    def _check_response_for_errors(self, response: dict[str, Any]) -> None:
        """Checks for errors in the API response.

        If an error is found, an exception is raised.
        A null responseHeader passes through unchecked; a missing one raises.
        retCode known values:
        - S: success
        - F: failure
        resCode / resMsg known values:
        - 0000: no error
        - 7110: OTP Required (MFA verification needed)
        - 7312: PIN mismatch (verify-PIN, #1565)
        - 7313: PIN token expired (verify-PIN, #1565)
        - 7314: PIN authentication failed (verify-PIN, #1565)
        - 7316: PIN locked (verify-PIN; reset on the vehicle or web)
        - 7401: Wrong credential
        - 7402 / 7530 / 7531 / 7532: Account Locked Out
        - 7403: Authentication expired
        - 7404 / 7435: Wrong username/password / account does not exist
        - 7445: Request could not be processed
        - 7549: Portal login captcha challenge required (
          Hyundai-Kia-Connect/kia_uvo#2025)
        - 7602: Access token deleted
        - 7603: Incorrect password
        - 7710: Device ID is not valid

        :param response: the API's JSON response
        """

        error_code_mapping = {
            "7401": AuthenticationInvalidCredentialsError,  # Wrong credential
            "7404": AuthenticationInvalidCredentialsError,
            "7435": AuthenticationInvalidCredentialsError,  # Account does not exist
            "7603": AuthenticationInvalidCredentialsError,  # Incorrect password
            "7312": AuthenticationInvalidCredentialsError,  # PIN mismatch
            "7314": AuthenticationInvalidCredentialsError,  # PIN auth failed
            "7313": AuthenticationTokenExpiredError,  # PIN token expired
            "7316": AuthenticationBlockedError,  # PIN locked
            "7402": AuthenticationBlockedError,  # Account locked out (7530-7532)
            "7530": AuthenticationBlockedError,
            "7531": AuthenticationBlockedError,
            "7532": AuthenticationBlockedError,
            "7403": AuthenticationTokenExpiredError,  # Expired - triggers re-login
            "7602": AuthenticationTokenExpiredError,  # Access token deleted
            "7549": AuthenticationError,  # Portal login captcha challenge
            "15109": UnsupportedControlError,  # Command body rejected for the vehicle
        }
        if response.get("responseHeader") is None and "responseHeader" in response:
            return
        response_code = response.get("responseHeader", {}).get("responseCode")
        if response_code is None:
            raise APIError(f"Unexpected response shape: {response}")
        if response_code == 1:
            error = response.get("error")
            if not isinstance(error, dict):
                raise APIError(f"Unexpected error response shape: {response}")
            error_code = error.get("errorCode")
            # Don't raise error for 7110 - it's handled in login method
            if error_code == "7110":
                return
            if error_code in error_code_mapping:
                raise error_code_mapping[error_code](error.get("errorDesc", error_code))
            raise APIError(
                f"Server returned: '{error.get('errorDesc', error.get('errorCode', 'unknown'))}'"
            )

    def login(
        self,
        username: str,
        password: str,
        pin: str | None = None,
    ) -> Token | OTPRequest:
        # Sign In with Email and Password and Get Authorization Code
        url = self.API_URL + "v2/login"
        data = {"loginId": username, "password": password}
        headers = self.API_HEADERS.copy()
        headers.pop("accessToken", None)

        # Use deterministic device ID based on MAC address to avoid OTP triggers
        device_id = self._get_device_id()
        _LOGGER.debug(f"{DOMAIN} - Using deterministic device ID")

        headers["Deviceid"] = device_id
        response = self.sessions.post(url, json=data, headers=headers)
        try:
            response_json = response.json()
        except ValueError as err:
            raise APIError(
                f"Login returned a non-JSON response (HTTP {response.status_code}, "
                f"server={response.headers.get('server')}, "
                f"cf-ray={response.headers.get('cf-ray')}): {response.text[:200]!r}"
            ) from err

        # Check if OTP is required (error code 7110)
        if (
            response_json["responseHeader"]["responseCode"] == 1
            and response_json.get("error", {}).get("errorCode") == "7110"
        ):
            _LOGGER.info(f"{DOMAIN} - OTP verification required for new device")

            # Call mfa/selverifmeth to get userInfoUuid and available methods
            selverifmeth_url = self.API_URL + "mfa/selverifmeth"
            selverifmeth_headers = self.API_HEADERS.copy()
            selverifmeth_headers.pop("accessToken", None)
            selverifmeth_headers["Deviceid"] = self._get_device_id()
            selverifmeth_data = {"mfaApiCode": "0107", "userAccount": username}

            selverifmeth_response = self.sessions.post(
                selverifmeth_url, json=selverifmeth_data, headers=selverifmeth_headers
            )
            _LOGGER.debug(
                f"{DOMAIN} - Select Verification Method Response {selverifmeth_response.text}"
            )
            selverifmeth_json = selverifmeth_response.json()

            # Check for errors
            if selverifmeth_json.get("responseHeader", {}).get("responseCode") != 0:
                error_desc = selverifmeth_json.get("error", {}).get(
                    "errorDesc", "Unknown error"
                )
                raise APIError(f"Failed to get verification methods: {error_desc}")

            # Extract userInfoUuid and emailList
            result = selverifmeth_json.get("result", {})
            user_info_uuid = result.get("userInfoUuid")
            email_list = result.get("emailList", [])
            phone = result.get("userPhone")

            return OTPRequest(
                request_id=user_info_uuid,
                otp_key=None,
                has_email=True,
                has_sms=bool(phone),
                email=email_list[0] if email_list else username,
                sms=phone,
            )

        # Check for other errors
        self._check_response_for_errors(response_json)

        # Normal login successful
        response_data = response_json["result"]["token"]
        token_expire_in = int(response_data["expireIn"]) - 60
        access_token = response_data["accessToken"]
        refresh_token = response_data["refreshToken"]

        valid_until = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=token_expire_in)

        return Token(
            username=username,
            password=password,
            access_token=access_token,
            refresh_token=refresh_token,
            device_id=self._get_device_id(),
            valid_until=valid_until,
            pin=pin,
        )

    def refresh_access_token(self, token: Token) -> Token | OTPRequest:
        """Refresh via gtothbyrftkn (Hyundai; SPA host) or re-login (Kia/Genesis, the proven pre-#1496 path).

        The Hyundai app refreshes with POST gtothbyrftkn (refresh token in the
        body, SPA headers, no accessToken); CWP carries the 7549 captcha
        challenge (Hyundai-Kia-Connect/kia_uvo#2025). Failure falls back to
        re-login, carrying the persisted device_id (
        Hyundai-Kia-Connect/kia_uvo#1715). kiaconnect.ca rejects SPA-shaped
        v2/login (7404), so Kia/Genesis re-login instead: the pre-#1496
        behavior without the 7602 freeze.
        """
        if token.device_id:
            self._device_id = token.device_id
        if BRANDS[self.brand] == BRAND_KIA:
            # kiaconnect.ca rejects SPA-shaped v2/login (7404, measured); the app logs in via
            # Kia-Account OAuth, so the portal profile mints through a full re-login (pre-#1496)
            return self.login(
                username=token.username, password=token.password, pin=token.pin
            )
        if token.refresh_token:
            url = self.API_URL + "gtothbyrftkn"
            data = {"refTokenData": token.refresh_token}
            headers = self.API_HEADERS.copy()
            headers.pop("accessToken", None)
            headers["Deviceid"] = self._get_device_id()
            try:
                response = self.sessions.post(url, json=data, headers=headers)
                response_json = response.json()
                if response_json["responseHeader"]["responseCode"] == 0:
                    response_data = response_json["result"]
                    token_expire_in = int(response_data["expireIn"]) - 60
                    valid_until = dt.datetime.now(dt.UTC) + dt.timedelta(
                        seconds=token_expire_in
                    )
                    return Token(
                        username=token.username,
                        password=token.password,
                        access_token=response_data["accessToken"],
                        refresh_token=response_data["refreshToken"],
                        device_id=self._get_device_id(),
                        valid_until=valid_until,
                        pin=token.pin,
                    )
                _LOGGER.debug(f"{DOMAIN} - Refresh rejected: {response_json}")
            except Exception:
                _LOGGER.debug(
                    f"{DOMAIN} - Refresh request failed; falling back to login"
                )

        return self.login(
            username=token.username, password=token.password, pin=token.pin
        )

    def send_otp(self, otp_request: OTPRequest, notify_type: OTP_NOTIFY_TYPE) -> None:
        """Sends OTP to the user via selected destination"""
        url = self.API_URL + "mfa/sendotp"
        headers = self.API_HEADERS.copy()
        headers["Deviceid"] = self._get_device_id()
        if notify_type == OTP_NOTIFY_TYPE.EMAIL:
            data = {
                "otpMethod": "E",
                "mfaApiCode": "0107",
                "userAccount": otp_request.email,
                "userPhone": "",
                "userInfoUuid": otp_request.request_id,
            }
        elif notify_type == OTP_NOTIFY_TYPE.SMS:
            data = {
                "otpMethod": "S",
                "mfaApiCode": "0107",
                "userAccount": otp_request.email,
                "userPhone": otp_request.sms,
                "userInfoUuid": otp_request.request_id,
            }
        else:  # Should never happen due to enum, but just in case
            raise ValueError("Invalid notify type")

        response = self.sessions.post(url, headers=headers, json=data)
        _LOGGER.debug(f"{DOMAIN} - Send OTP Response {response.text}")
        response_json = response.json()

        if response_json["responseHeader"]["responseCode"] != 0:
            error_desc = response_json.get("error", {}).get(
                "errorDesc", "Unknown error"
            )
            raise APIError(f"Failed to send OTP: {error_desc}")

        otp_key = response_json["result"]["otpKey"]
        otp_request.otp_key = otp_key

    def verify_otp_and_complete_login(
        self,
        username: str,
        password: str,
        otp_code: str,
        otp_request: OTPRequest,
        pin: str | None = None,
    ) -> Token:
        """Confirms OTP code sent to the user and completes login"""
        url = self.API_URL + "mfa/validateotp"
        headers = self.API_HEADERS.copy()
        headers["Deviceid"] = self._get_device_id()
        data = {
            "otpNo": otp_code,
            "userAccount": username,
            "otpKey": otp_request.otp_key,
            "mfaApiCode": "0107",
        }

        response = self.sessions.post(url, headers=headers, json=data)
        _LOGGER.debug(f"{DOMAIN} - Verify OTP Response {response.text}")
        response_json = response.json()

        if response_json["responseHeader"]["responseCode"] != 0:
            error_desc = response_json.get("error", {}).get(
                "errorDesc", "Invalid OTP code"
            )
            raise AuthenticationError(f"OTP verification failed: {error_desc}")

        if not response_json["result"].get("verifiedOtp", False):
            raise AuthenticationError("OTP verification failed")

        otp_validation_key = response_json["result"]["otpValidationKey"]

        # Call mfa/genmfatkn to get the access token and refresh token
        genmfatkn_url = self.API_URL + "mfa/genmfatkn"
        genmfatkn_headers = self.API_HEADERS.copy()
        genmfatkn_headers["Deviceid"] = self._get_device_id()
        genmfatkn_data = {
            "userAccount": username,
            "otpEmail": otp_request.email,
            "mfaApiCode": "0107",
            "otpValidationKey": otp_validation_key,
            "mfaYn": "Y",
        }

        genmfatkn_response = self.sessions.post(
            genmfatkn_url, json=genmfatkn_data, headers=genmfatkn_headers
        )
        genmfatkn_json = genmfatkn_response.json()

        if genmfatkn_json["responseHeader"]["responseCode"] != 0:
            error_desc = genmfatkn_json.get("error", {}).get(
                "errorDesc", "Token generation failed"
            )
            raise AuthenticationError(f"Failed to generate token: {error_desc}")

        token_data = genmfatkn_json["result"]["token"]
        token_expire_in = int(token_data["expireIn"]) - 60
        access_token = token_data["accessToken"]
        refresh_token = token_data["refreshToken"]

        valid_until = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=token_expire_in)

        return Token(
            username=username,
            password=password,
            access_token=access_token,
            refresh_token=refresh_token,
            device_id=self._get_device_id(),
            valid_until=valid_until,
            pin=pin,
        )

    def test_token(self, token: Token) -> bool:
        # Use "get vehicle list" to test the token and keep it alive
        # Calling this endpoint every 5 minutes prevents the accessToken from expiring
        url = self.API_URL + "vhcllst"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        response = self.sessions.post(url, headers=headers)
        _LOGGER.debug(f"{DOMAIN} - Test Token Response {response.text}")
        response = response.json()
        # 7403/7602: token expired/deleted. 7606: CA binds the access token to
        # the IP that issued it, and rejects it outright if the caller's IP has
        # since changed (e.g. an ISP lease renewal around a nightly HA restart)
        # rather than expiring it normally. Treating 7606 as valid left
        # check_and_refresh_token() reusing the stale token, which then failed
        # again in get_vehicles() as an unhandled APIError (Hyundai-Kia-Connect/kia_uvo#1715).
        token_errors = ["7403", "7602", "7606"]
        return not (
            response["responseHeader"]["responseCode"] == 1
            and response["error"]["errorCode"] in token_errors
        )

    def get_vehicles(self, token: Token) -> list[Vehicle]:
        url = self.API_URL + "vhcllst"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        response = self.sessions.post(url, headers=headers)
        _LOGGER.debug(f"{DOMAIN} - Get Vehicles Response {response.text}")
        response = response.json()

        # Check for errors (including 7602 - access token deleted)
        self._check_response_for_errors(response)

        result = []
        for entry in response["result"]["vehicles"]:
            entry_engine_type = None
            if entry["fuelKindCode"] == "G":
                entry_engine_type = ENGINE_TYPES.ICE
            elif entry["fuelKindCode"] == "E":
                entry_engine_type = ENGINE_TYPES.EV
            elif entry["fuelKindCode"] == "P":
                entry_engine_type = ENGINE_TYPES.PHEV
            vehicle: Vehicle = Vehicle(
                id=entry["vehicleId"],
                name=entry["nickName"],
                model=entry.get("modelName"),
                year=int(entry.get("modelYear", 1900)),
                VIN=entry["vin"],
                engine_type=entry_engine_type,
                timezone=self.data_timezone,
                dtc_count=entry["dtcCount"],
                generation=entry.get("genType"),
            )
            vehicle.connect_subscription_end_date = _ymd_date(
                entry.get("subscriptionEndDate")
            )
            vehicle.supports.window_control = False
            # kiaconnect.ca exposes valet/activate, valet/deactivate and
            # valet/lastvaletstatus (see valet_mode_action).
            vehicle.supports.valet_mode = True
            vehicle.supports.svm = False
            result.append(vehicle)
        return result

    def update_vehicle_with_cached_state(self, token: Token, vehicle: Vehicle) -> None:
        state = self._get_cached_vehicle_state(token, vehicle)
        self._update_vehicle_properties_base(vehicle, state)

        # Service Status Call
        service = self._get_next_service(token, vehicle)

        # Get location if the car has moved since last call, or if no location
        # is known yet: coordinates live only in the in-memory Vehicle object,
        # so after a restart/reload a parked car would otherwise never get a
        # location fetch and the location sensors stay unavailable until the
        # car physically moves (Hyundai-Kia-Connect/kia_uvo#1844). The
        # unknown-location fetch is bounded to one attempt per session (the
        # flag is in-memory like the coordinates) so a persistently failing
        # Find-My-Car response cannot re-run on every poll.
        if vehicle.odometer:
            if vehicle.odometer < get_child_value(service, "currentOdometer") or (
                vehicle.location_latitude is None
                and not vehicle._location_fetch_attempted
            ):
                if vehicle.location_latitude is None:
                    vehicle._location_fetch_attempted = True
                location = self._get_location(token, vehicle)
                self._update_vehicle_properties_location(vehicle, location)
        else:
            location = self._get_location(token, vehicle)
            self._update_vehicle_properties_location(vehicle, location)

        # Update service after the fact so we still have the old odometer
        # reading available for above.
        self._update_vehicle_properties_service(vehicle, service)
        self._update_maintenance_report(token, vehicle)
        if vehicle.engine_type == ENGINE_TYPES.EV:
            charge = self._get_charge_limits(token, vehicle)
            self._update_vehicle_properties_charge(vehicle, charge)
            self._update_vehicle_properties_trip_details(token, vehicle)
            self._update_charge_schedule(token, vehicle)
            self._update_account_extras(token, vehicle)

    def force_refresh_vehicle_state(self, token: Token, vehicle: Vehicle) -> None:
        state = self._get_forced_vehicle_state(token, vehicle)

        # lastStatusDate uses one of the Canadian timezones configured through
        # the car entertainment system.
        last_updated_at = parse_datetime(
            get_child_value(state, "status.lastStatusDate"), dt.UTC
        )
        ref_date = dt.datetime.now(tz=dt.UTC)
        if last_updated_at is None:
            _LOGGER.debug(f"{DOMAIN} - no lastStatusDate; skipping timezone guess")
        elif (
            abs(raw_delta_seconds := (ref_date - last_updated_at).total_seconds())
            < 20 * 60
        ):
            # Timestamp is already in UTC (e.g. fresh forced-refresh response);
            # reinterpreting it as a Canadian local time would always fail — skip silently.
            _LOGGER.debug(
                f"{DOMAIN} - lastStatusDate delta is {raw_delta_seconds:.1f}s; "
                "skipping Canadian timezone guess (timestamp appears to be UTC)"
            )
        else:
            tz = detect_timezone_for_date(last_updated_at, ref_date, CA_TIMEZONES)
            if tz:
                _LOGGER.debug(f"{DOMAIN} - Set vehicle.timezone to {tz} (guessed)")
                vehicle.timezone = tz
            else:
                _LOGGER.warning(
                    f"{DOMAIN} - could not guess Canadian timezone! "
                    f"delta is {raw_delta_seconds / 3600} hours"
                )

        self._update_vehicle_properties_base(vehicle, state)

        # Service Status Call
        service = self._get_next_service(token, vehicle)

        # Get location if the car has moved since last call, or if no location
        # is known yet (same restart/reload rationale and same one-attempt
        # bound as the cached-state path above,
        # Hyundai-Kia-Connect/kia_uvo#1844).
        if vehicle.odometer:
            if vehicle.odometer < get_child_value(service, "currentOdometer") or (
                vehicle.location_latitude is None
                and not vehicle._location_fetch_attempted
            ):
                if vehicle.location_latitude is None:
                    vehicle._location_fetch_attempted = True
                location = self._get_location(token, vehicle)
                self._update_vehicle_properties_location(vehicle, location)
        else:
            location = self._get_location(token, vehicle)
            self._update_vehicle_properties_location(vehicle, location)

        # Update service after the fact so we still have the old odometer
        # reading available for above.
        self._update_vehicle_properties_service(vehicle, service)
        self._update_maintenance_report(token, vehicle)

        if vehicle.engine_type == ENGINE_TYPES.EV:
            charge = self._get_charge_limits(token, vehicle)
            self._update_vehicle_properties_charge(vehicle, charge)
            self._update_vehicle_properties_trip_details(token, vehicle)
            self._update_charge_schedule(token, vehicle)
            self._update_account_extras(token, vehicle)

    def _update_maintenance_report(self, token: Token, vehicle: Vehicle) -> None:
        """Fetch the newest monthly maintenance report when a new one appears.

        The list call runs on every update (same per-poll pattern as the
        next-service read); the report is re-fetched only when its id changes.
        """
        report_list = self._get_mvr_list(token, vehicle)
        reports = report_list.get("MVRs") if isinstance(report_list, dict) else None
        if not reports:
            return
        if get_child_value(reports[0], "reportId") in (
            None,
            vehicle.maintenance_report_last_id,
        ):
            return
        vehicle.maintenance_report_last_id = get_child_value(reports[0], "reportId")
        vehicle.maintenance_report_date = get_child_value(reports[0], "reportDate")
        report = self._get_mvr_report(
            token, vehicle, vehicle.maintenance_report_last_id
        )
        vehicle.maintenance_report_odometer = get_child_value(report, "odometer")
        vehicle.maintenance_report_odometer_unit = report.get("odometerUnitStr")
        vehicle.maintenance_report_systems = get_child_value(report, "systems")

    def _get_mvr_list(self, token: Token, vehicle: Vehicle) -> dict[str, Any]:
        url = self.API_URL + "gtmvrlst"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        response = self.sessions.post(url, headers=headers, json={})
        response_json = response.json()
        self._check_response_for_errors(response_json)
        return response_json.get("result") or {}

    def _get_mvr_report(
        self, token: Token, vehicle: Vehicle, report_id: int
    ) -> dict[str, Any]:
        url = self.API_URL + "gtmvrrpt"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        response = self.sessions.post(
            url, headers=headers, json={"reportId": report_id}
        )
        response_json = response.json()
        self._check_response_for_errors(response_json)
        return response_json.get("result", {}).get("MVR") or {}

    def _update_vehicle_properties_base(
        self, vehicle: Vehicle, state: dict[str, Any]
    ) -> None:
        _LOGGER.debug(f"{DOMAIN} - Old Vehicle Last Updated: {vehicle.last_updated_at}")
        vehicle.last_updated_at = parse_datetime(
            get_child_value(state, "status.lastStatusDate"), self.data_timezone
        )
        _LOGGER.debug(
            f"{DOMAIN} - Current Vehicle Last Updated: {vehicle.last_updated_at}"
        )
        # Converts temp to usable number. Currently only support celsius.
        # Future to do is check unit in case the care itself is set to F.
        if (
            get_child_value(state, "status.airTemp.value") is not None
            and get_child_value(state, "status.airTemp.value") != "OFF"
            and get_child_value(state, "status.airTemp.value")[-1] == "H"
        ):
            tempIndex = cast(
                int,
                get_hex_temp_into_index(get_child_value(state, "status.airTemp.value")),
            )
            if get_child_value(state, "status.airTemp.unit") == 0:
                if (
                    vehicle.year is not None
                    and vehicle.year >= self.temperature_range_model_year
                ):
                    state["status"]["airTemp"]["value"] = self.temperature_range_c_new[
                        tempIndex
                    ]

                else:
                    state["status"]["airTemp"]["value"] = self.temperature_range_c_old[
                        tempIndex
                    ]

        vehicle.total_driving_range = (
            get_child_value(
                state,
                "status.evStatus.drvDistance.0.rangeByFuel.totalAvailableRange.value",
            ),
            DISTANCE_UNITS[
                get_child_value(
                    state,
                    "status.evStatus.drvDistance.0.rangeByFuel.totalAvailableRange.unit",
                )
            ],
        )

        vehicle.car_battery_percentage = normalize_battery_soc(
            get_child_value(state, "status.battery.batSoc")
        )
        vehicle.engine_is_running = get_child_value(state, "status.engine")
        vehicle.washer_fluid_warning_is_on = get_child_value(
            state, "status.washerFluidStatus"
        )
        vehicle.brake_fluid_warning_is_on = get_child_value(
            state, "status.breakOilStatus"
        )
        vehicle.tire_pressure_rear_left_warning_is_on = bool(
            get_child_value(state, "status.tirePressureLamp.tirePressureLampRL")
        )
        vehicle.tire_pressure_front_left_warning_is_on = bool(
            get_child_value(state, "status.tirePressureLamp.tirePressureLampFL")
        )
        vehicle.tire_pressure_front_right_warning_is_on = bool(
            get_child_value(state, "status.tirePressureLamp.tirePressureLampFR")
        )
        vehicle.tire_pressure_rear_right_warning_is_on = bool(
            get_child_value(state, "status.tirePressureLamp.tirePressureLampRR")
        )
        vehicle.tire_pressure_all_warning_is_on = bool(
            get_child_value(state, "status.tirePressureLamp.tirePressureLampAll")
        )
        vehicle.air_temperature = (
            get_child_value(state, "status.airTemp.value"),
            TEMPERATURE_UNITS[0],
        )
        vehicle.defrost_is_on = get_child_value(state, "status.defrost")
        vehicle.steering_wheel_heater_is_on = get_child_value(
            state, "status.steerWheelHeat"
        )
        # 2-step wheels (StrgWhlHeatingOption 2) report 0 off, 1 low, 2 high
        vehicle.steering_wheel_heat_step = int_or_none(
            get_child_value(state, "status.steerWheelHeat_step2")
        )
        vehicle.back_window_heater_is_on = get_child_value(
            state, "status.sideBackWindowHeat"
        )
        vehicle.side_mirror_heater_is_on = get_child_value(
            state, "status.sideMirrorHeat"
        )
        # lstvhclsts reports seats under seatHeaterVentInfo keyed driver/assist;
        # Canada is LHD, so driver is front left.
        seat_info = get_child_value(state, "status.seatHeaterVentInfo") or {}
        seat_state = get_child_value(state, "status.seatHeaterVentState") or {}
        vehicle.front_left_seat_status = SEAT_STATUS.get(
            seat_info.get("drvSeatHeatState", seat_state.get("flSeatHeatState"))
        )
        vehicle.front_right_seat_status = SEAT_STATUS.get(
            seat_info.get("astSeatHeatState", seat_state.get("frSeatHeatState"))
        )
        vehicle.rear_left_seat_status = SEAT_STATUS.get(
            seat_info.get("rlSeatHeatState", seat_state.get("rlSeatHeatState"))
        )
        vehicle.rear_right_seat_status = SEAT_STATUS.get(
            seat_info.get("rrSeatHeatState", seat_state.get("rrSeatHeatState"))
        )
        # Additional status fields observed in logs (exposed as binary sensors)
        vehicle.accessory_on = get_child_value(state, "status.acc")
        vehicle.ign3 = get_child_value(state, "status.ign3")
        vehicle.remote_ignition = get_child_value(state, "status.remoteIgnition")
        vehicle.transmission_condition = get_child_value(state, "status.transCond")
        vehicle.sleep_mode_check = get_child_value(state, "status.sleepModeCheck")

        # lamp wire status (nested)
        vehicle.headlamp_status = get_child_value(
            state, "status.lampWireStatus.headLamp.headLampStatus"
        )
        vehicle.headlamp_left_low = get_child_value(
            state, "status.lampWireStatus.headLamp.leftLowLamp"
        )
        vehicle.headlamp_right_low = get_child_value(
            state, "status.lampWireStatus.headLamp.rightLowLamp"
        )
        vehicle.headlamp_left_high = get_child_value(
            state, "status.lampWireStatus.headLamp.leftHighLamp"
        )
        vehicle.headlamp_right_high = get_child_value(
            state, "status.lampWireStatus.headLamp.rightHighLamp"
        )
        vehicle.headlamp_left_bifunc = get_child_value(
            state, "status.lampWireStatus.headLamp.leftBifuncLamp"
        )
        vehicle.headlamp_right_bifunc = get_child_value(
            state, "status.lampWireStatus.headLamp.rightBifuncLamp"
        )
        vehicle.stop_lamp_left = get_child_value(
            state, "status.lampWireStatus.stopLamp.leftLamp"
        )
        vehicle.stop_lamp_right = get_child_value(
            state, "status.lampWireStatus.stopLamp.rightLamp"
        )
        vehicle.turn_signal_left_front = get_child_value(
            state, "status.lampWireStatus.turnSignalLamp.leftFrontLamp"
        )
        vehicle.turn_signal_right_front = get_child_value(
            state, "status.lampWireStatus.turnSignalLamp.rightFrontLamp"
        )
        vehicle.turn_signal_left_rear = get_child_value(
            state, "status.lampWireStatus.turnSignalLamp.leftRearLamp"
        )
        vehicle.turn_signal_right_rear = get_child_value(
            state, "status.lampWireStatus.turnSignalLamp.rightRearLamp"
        )
        vehicle.is_locked = get_child_value(state, "status.doorLock")
        vehicle.front_left_door_is_open = get_child_value(
            state, "status.doorOpen.frontLeft"
        )
        vehicle.front_right_door_is_open = get_child_value(
            state, "status.doorOpen.frontRight"
        )
        vehicle.back_left_door_is_open = get_child_value(
            state, "status.doorOpen.backLeft"
        )
        vehicle.back_right_door_is_open = get_child_value(
            state, "status.doorOpen.backRight"
        )
        vehicle.hood_is_open = get_child_value(state, "status.hoodOpen")
        vehicle.sunroof_is_open = get_child_value(state, "status.sunroofOpen")

        vehicle.trunk_is_open = get_child_value(state, "status.trunkOpen")
        vehicle.front_left_window_is_open = get_child_value(
            state, "status.windowOpen.frontLeft"
        )
        vehicle.front_right_window_is_open = get_child_value(
            state, "status.windowOpen.frontRight"
        )
        vehicle.back_left_window_is_open = get_child_value(
            state, "status.windowOpen.backLeft"
        )
        vehicle.back_right_window_is_open = get_child_value(
            state, "status.windowOpen.backRight"
        )
        if vehicle.engine_type != ENGINE_TYPES.ICE:
            vehicle.ev_battery_percentage = get_child_value(
                state, "status.evStatus.batteryStatus"
            )
            vehicle.ev_battery_is_charging = get_child_value(
                state, "status.evStatus.batteryCharge"
            )
            vehicle.ev_battery_is_plugged_in = get_child_value(
                state, "status.evStatus.batteryPlugin"
            )
            vehicle.ev_driving_range = (
                get_child_value(
                    state,
                    "status.evStatus.drvDistance.0.rangeByFuel.evModeRange.value",
                ),
                DISTANCE_UNITS[
                    get_child_value(
                        state,
                        "status.evStatus.drvDistance.0.rangeByFuel.evModeRange.unit",
                    )
                ],
            )
            vehicle.ev_estimated_current_charge_duration = (
                get_child_value(state, "status.evStatus.remainTime2.atc.value"),
                "m",
            )
            vehicle.ev_estimated_fast_charge_duration = (
                get_child_value(state, "status.evStatus.remainTime2.etc1.value"),
                "m",
            )
            vehicle.ev_estimated_portable_charge_duration = (
                get_child_value(state, "status.evStatus.remainTime2.etc2.value"),
                "m",
            )
            vehicle.ev_estimated_station_charge_duration = (
                get_child_value(state, "status.evStatus.remainTime2.etc3.value"),
                "m",
            )
            vehicle.ev_battery_precondition_enabled = get_child_value(
                state, "status.evStatus.batteryPreconditiong"
            )
            vehicle.ev_estimated_station_charge_duration = (
                get_child_value(state, "status.evStatus.remainTime2.etc3.value"),
                "m",
            )
        vehicle.fuel_driving_range = (
            get_child_value(
                state,
                "status.evStatus.drvDistance.0.rangeByFuel.gasModeRange.value",
            ),
            DISTANCE_UNITS[
                get_child_value(
                    state, "status.evStatus.drvDistance.0.rangeByFuel.gasModeRange.unit"
                )
            ],
        )
        if vehicle.fuel_driving_range is None:
            vehicle.fuel_driving_range = (
                get_child_value(
                    state,
                    "status.dte.value",
                ),
                DISTANCE_UNITS[get_child_value(state, "status.dte.unit")],
            )

        vehicle.fuel_level_is_low = get_child_value(state, "status.lowFuelLight")
        vehicle.fuel_level = get_child_value(state, "status.fuelLevel")
        vehicle.air_control_is_on = get_child_value(state, "status.airCtrlOn")
        vehicle.smart_key_battery_warning_is_on = get_child_value(
            state, "status.smartKeyBatteryWarning"
        )
        oil = get_child_value(state, "status.engineOilStatus")
        if oil is not None:
            vehicle.oil_level_warning_is_on = bool(oil)
        soh = get_child_value(state, "status.evStatus.batterySoh")
        if soh is not None:
            vehicle.ev_battery_soh_percentage = int_or_none(soh)
        discharge_limit = get_child_value(state, "status.evStatus.dischargingLimit")
        if discharge_limit is not None:
            vehicle.ev_v2l_discharge_limit = int_or_none(discharge_limit)
        self._update_departures(
            vehicle, get_child_value(state, "status.evStatus.reservChargeInfos")
        )
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["status"] = state["status"]

    def _departure_temperature(self, vehicle: Vehicle, raw: Any) -> float | None:
        """lstvhclsts reports "23.0"; schedule bodies use the hex index ("10H")."""
        if raw is None:
            return None
        text = str(raw)
        if text.upper().endswith("H"):
            index = get_hex_temp_into_index(text)
            table = (
                self.temperature_range_c_new
                if vehicle.year is not None
                and vehicle.year >= self.temperature_range_model_year
                else self.temperature_range_c_old
            )
            if index is None or not 0 <= index < len(table):
                return None
            return table[index]
        try:
            return float(text)
        except ValueError:
            return None

    def _update_departures(self, vehicle: Vehicle, infos: Any) -> None:
        """Departure (scheduled climate) slots from reservChargeInfos."""
        if not isinstance(infos, dict):
            return
        for number, status_key, _ in _CA_DEPARTURE_SLOTS:
            detail = get_child_value(infos, f"{status_key}.reservChargeInfoDetail")
            if not isinstance(detail, dict):
                continue
            prefix = "first" if number == 1 else "second"
            days = get_child_value(detail, "reservInfo.day") or []
            fatc = detail.get("reservFatcSet") or {}
            setattr(
                vehicle,
                f"ev_{prefix}_departure_enabled",
                bool(detail.get("reservChargeSet")),
            )
            setattr(
                vehicle,
                f"ev_{prefix}_departure_days",
                sorted(d for d in days if isinstance(d, int) and 0 <= d <= 6),
            )
            setattr(
                vehicle,
                f"ev_{prefix}_departure_time",
                _reservation_time(get_child_value(detail, "reservInfo.time")),
            )
            setattr(
                vehicle,
                f"ev_{prefix}_departure_climate_enabled",
                bool(fatc.get("airCtrl")),
            )
            setattr(
                vehicle,
                f"ev_{prefix}_departure_climate_defrost",
                bool(fatc.get("defrost")),
            )
            temperature = self._departure_temperature(
                vehicle, get_child_value(fatc, "airTemp.value")
            )
            if temperature is not None:
                setattr(
                    vehicle,
                    f"ev_{prefix}_departure_climate_temperature",
                    (temperature, TEMPERATURE_UNITS[0]),
                )

    def _update_vehicle_properties_service(
        self, vehicle: Vehicle, state: dict[str, Any]
    ) -> None:
        vehicle.odometer = (
            get_child_value(state, "currentOdometer"),
            DISTANCE_UNITS[get_child_value(state, "currentOdometerUnit")],
        )
        vehicle.next_service_distance = (
            get_child_value(state, "imatServiceOdometer"),
            DISTANCE_UNITS[get_child_value(state, "imatServiceOdometerUnit")],
        )
        vehicle.last_service_distance = (
            get_child_value(state, "msopServiceOdometer"),
            DISTANCE_UNITS[get_child_value(state, "msopServiceOdometerUnit")],
        )
        vehicle.next_service_date = _ymd_date(get_child_value(state, "mtitServiceDate"))
        vehicle.last_service_date = _ymd_date(get_child_value(state, "mtspServiceDate"))
        vehicle.service_interval_distance = get_child_value(
            state, "serviceOdometerDuration"
        )
        vehicle.service_interval_months = int_or_none(
            get_child_value(state, "serviceMonthsThreshold")
        )

        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["service"] = state

    def _update_vehicle_properties_location(
        self, vehicle: Vehicle, state: dict[str, Any] | None
    ) -> None:
        if get_child_value(state, "coord.lat"):
            vehicle.location = (
                get_child_value(state, "coord.lat"),
                get_child_value(state, "coord.lon"),
                parse_datetime(get_child_value(state, "time"), self.data_timezone),
            )
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["vehicleLocation"] = state

    def _update_vehicle_properties_trip_details(
        self, token: Token, vehicle: Vehicle
    ) -> None:
        url = self.API_URL + "alerts/maintenance/evTripDetails"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id

        response = self.sessions.post(url, headers=headers)
        if response.ok:
            response = response.json()
            _LOGGER.debug(
                f"{DOMAIN} - Received _update_vehicle_properties_trip_details response {response}"
            )

            # Check for errors (including 7602 - access token deleted)
            self._check_response_for_errors(response)

            if "result" in response and "tripdetails" in response["result"]:
                trip_stats = []
                for trip in response["result"]["tripdetails"]:
                    processed_trip = DailyDrivingStats(
                        date=dt.datetime.strptime(
                            trip["startdate"], "%Y-%m-%d %H:%M:%S"
                        ),
                        total_consumed=get_child_value(trip, "totalused"),
                        engine_consumption=get_child_value(trip, "drivetrain"),
                        climate_consumption=get_child_value(trip, "climate"),
                        onboard_electronics_consumption=get_child_value(
                            trip, "accessories"
                        ),
                        battery_care_consumption=get_child_value(trip, "batterycare"),
                        regenerated_energy=get_child_value(trip, "regen"),
                        distance=get_child_value(trip, "distance"),
                        distance_unit=vehicle.odometer_unit,
                    )
                    trip_stats.append(processed_trip)
                vehicle.daily_stats = trip_stats
            else:
                _LOGGER.debug(
                    f"{DOMAIN} - Error with _update_vehicle_properties_trip_details response. Unknown format: {response}"
                )
        else:
            _LOGGER.debug(
                f"{DOMAIN} - Error with _update_vehicle_properties_trip_details response: {response.text}"
            )

    def _get_cached_vehicle_state(
        self, token: Token, vehicle: Vehicle
    ) -> dict[str, Any]:
        # Vehicle Status Call
        url = self.API_URL + "lstvhclsts"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id

        response = self.sessions.post(url, headers=headers)
        response = response.json()
        _LOGGER.debug(f"{DOMAIN} - get_cached_vehicle_status response {response}")

        # Check for errors (including 7602 - access token deleted)
        self._check_response_for_errors(response)

        response = response["result"]["status"]

        status = {}
        status["status"] = response

        return status

    def _get_forced_vehicle_state(
        self, token: Token, vehicle: Vehicle
    ) -> dict[str, Any]:
        url = self.API_URL + "rltmvhclsts"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id

        response = self.sessions.post(url, headers=headers)
        response = response.json()

        _LOGGER.debug(f"{DOMAIN} - Received forced vehicle data {response}")

        # Check for errors (including 7602 - access token deleted)
        self._check_response_for_errors(response)

        response = response["result"]["status"]
        status = {}
        status["status"] = response

        return status

    def _get_next_service(self, token: Token, vehicle: Vehicle) -> dict[str, Any]:
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        url = self.API_URL + "nxtsvc"
        response = self.sessions.post(url, headers=headers)
        response = response.json()
        _LOGGER.debug(f"{DOMAIN} - Get Service status data {response}")

        # Check for errors (including 7602 - access token deleted)
        self._check_response_for_errors(response)

        response = response["result"]["maintenanceInfo"]
        return cast(dict[str, Any], response)

    def _get_location(self, token: Token, vehicle: Vehicle) -> dict[str, Any] | None:
        url = self.API_URL + "fndmcr"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        # fndmcr refuses from:CWP with error 6459 (Hyundai-Kia-Connect/kia_uvo#1069)
        headers["from"] = "SPA"
        if BRANDS[self.brand] != BRAND_HYUNDAI:
            headers["Referer"] = f"https://{self.BASE_URL}/remote/"
        try:
            headers["pAuth"] = self._get_pin_token(token, vehicle)
            response = self.sessions.post(url, headers=headers, json={"pin": token.pin})
            response = response.json()
            _LOGGER.debug(f"{DOMAIN} - Get Vehicle Location {response}")
            if response["responseHeader"]["responseCode"] != 0:
                raise APIError("No Location Located")
            return cast(dict[str, Any] | None, response["result"])
        except Exception:
            _LOGGER.warning(f"{DOMAIN} - Get vehicle location failed")
            return None

    def _get_pin_token(self, token: Token, vehicle: Vehicle) -> str:
        url = self.API_URL + "vrfypin"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        response = self.sessions.post(url, headers=headers, json={"pin": token.pin})
        response_json = response.json()
        _LOGGER.debug(f"{DOMAIN} - Received Pin validation response {response_json}")
        self._check_response_for_errors(response_json)
        return cast(str, response_json["result"]["pAuth"])

    def lock_action(
        self, token: Token, vehicle: Vehicle, action: VEHICLE_LOCK_ACTION
    ) -> str:
        _LOGGER.debug(f"{DOMAIN} - Action for lock is: {action}")
        if action == VEHICLE_LOCK_ACTION.LOCK:
            url = self.API_URL + "drlck"
            _LOGGER.debug(f"{DOMAIN} - Calling Lock")
        elif action == VEHICLE_LOCK_ACTION.UNLOCK:
            url = self.API_URL + "drulck"
            _LOGGER.debug(f"{DOMAIN} - Calling unlock")
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)

        response = self.sessions.post(
            url, headers=headers, data=json.dumps({"pin": token.pin})
        )
        response_headers = response.headers
        response = response.json()

        _LOGGER.debug(f"{DOMAIN} - Received lock_action response {response}")
        self._check_response_for_errors(response)
        return response_headers["transactionId"]

    def start_climate(
        self, token: Token, vehicle: Vehicle, options: ClimateRequestOptions
    ) -> str:
        if vehicle.engine_type == ENGINE_TYPES.EV:
            url = self.API_URL + "evc/rfon"
        else:
            url = self.API_URL + "rmtstrt"
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)

        if options.climate is None:
            options.climate = True
        if options.set_temp is None:
            options.set_temp = 21
        if options.duration is None:
            options.duration = 5
        if options.heating is None:
            options.heating = 0
        if options.defrost is None:
            options.defrost = False
        if options.front_left_seat is None:
            options.front_left_seat = 0
        if options.front_right_seat is None:
            options.front_right_seat = 0
        if options.rear_left_seat is None:
            options.rear_left_seat = 0
        if options.rear_right_seat is None:
            options.rear_right_seat = 0

        if (
            vehicle.year is not None
            and vehicle.year >= self.temperature_range_model_year
        ):
            hex_set_temp = get_index_into_hex_temp(
                self.temperature_range_c_new.index(options.set_temp)
            )
        else:
            hex_set_temp = get_index_into_hex_temp(
                self.temperature_range_c_old.index(options.set_temp)
            )
        # Other G3 EVs try remoteControl first; some (Kona EV, IONIQ 6)
        # reject it with 6452 and accept hvacInfo.
        fallback = False
        if vehicle.engine_type == ENGINE_TYPES.EV:
            model = (vehicle.model or "").replace(" ", "").upper()
            if model in _CA_REMOTE_CONTROL_CLIMATE_MODELS:
                body_key = "remoteControl"
            elif (
                vehicle.generation == "G3"
                and vehicle.id not in self._hvac_info_climate_ids
            ):
                body_key = "remoteControl"
                fallback = True
            else:
                body_key = "hvacInfo"
            payload: dict[str, Any] = {
                "pin": token.pin,
                body_key: {
                    "airCtrl": int(options.climate),
                    "defrost": options.defrost,
                    "heating1": options.heating,
                    "airTemp": {
                        "value": hex_set_temp,
                        "unit": 0,
                        "hvacTempType": 1,
                    },
                    "igniOnDuration": options.duration,
                    "seatHeaterVentCMD": {
                        "drvSeatOptCmd": options.front_left_seat,
                        "astSeatOptCmd": options.front_right_seat,
                        "rlSeatOptCmd": options.rear_left_seat,
                        "rrSeatOptCmd": options.rear_right_seat,
                    },
                },
            }
            _add_steering_wheel_step(payload[body_key], options)
        else:
            payload = {
                "setting": {
                    "airCtrl": int(options.climate),
                    "defrost": options.defrost,
                    "heating1": options.heating,
                    "igniOnDuration": options.duration,
                    "ims": 0,
                    "airTemp": {"value": hex_set_temp, "unit": 0, "hvacTempType": 0},
                    "seatHeaterVentCMD": {
                        "drvSeatOptCmd": options.front_left_seat,
                        "astSeatOptCmd": options.front_right_seat,
                        "rlSeatOptCmd": options.rear_left_seat,
                        "rrSeatOptCmd": options.rear_right_seat,
                    },
                },
                "pin": token.pin,
            }
            _add_steering_wheel_step(payload["setting"], options)
        response_headers, response = self._post_start_climate(url, headers, payload)
        error = response.get("error")
        retry = (
            fallback and isinstance(error, dict) and error.get("errorCode") == "6452"
        )
        if retry:
            payload["hvacInfo"] = payload.pop("remoteControl")
            headers["pAuth"] = self._get_pin_token(token, vehicle)
            response_headers, response = self._post_start_climate(url, headers, payload)
        self._check_response_for_errors(response)
        if retry:
            self._hvac_info_climate_ids.add(vehicle.id)
        return response_headers["transactionId"]

    def _post_start_climate(
        self, url: str, headers: dict[str, Any], payload: dict[str, Any]
    ) -> tuple[requests.structures.CaseInsensitiveDict[str], dict[str, Any]]:
        _LOGGER.debug(
            f"{DOMAIN} - Planned start_climate payload {self._mask_sensitive_data(payload)}"
        )
        response = self.sessions.post(url, headers=headers, data=json.dumps(payload))
        body: dict[str, Any] = response.json()
        _LOGGER.debug(f"{DOMAIN} - Received start_climate response {body}")
        return response.headers, body

    def stop_climate(self, token: Token, vehicle: Vehicle) -> str:
        if vehicle.engine_type == ENGINE_TYPES.EV:
            url = self.API_URL + "evc/rfoff"
        else:
            url = self.API_URL + "rmtstp"
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)

        response = self.sessions.post(
            url, headers=headers, data=json.dumps({"pin": token.pin})
        )
        response_headers = response.headers
        response = response.json()

        _LOGGER.debug(f"{DOMAIN} - Received stop_climate response: {response}")
        self._check_response_for_errors(response)
        return response_headers["transactionId"]

    def check_action_status(
        self,
        token: Token,
        vehicle: Vehicle,
        action_id: str,
        synchronous: bool = False,
        timeout: int = 0,
    ) -> ORDER_STATUS:
        if timeout < 0:
            return ORDER_STATUS.TIMEOUT
        start_time = dt.datetime.now()

        url = self.API_URL + "rmtsts"
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["transactionId"] = action_id
        headers["pAuth"] = self._get_pin_token(token, vehicle)
        response = self.sessions.post(url, headers=headers)
        response = response.json()

        response = self.sessions.post(url, headers=headers)
        response = response.json()

        response_code = response.get("responseHeader", {}).get("responseCode")
        if response_code == 1:
            # Error envelope - no result/transaction block to read
            _LOGGER.debug(f"{DOMAIN} - Action status error response: {response}")
            return ORDER_STATUS.FAILED

        transaction = response.get("result", {}).get("transaction")
        if not isinstance(transaction, dict):
            raise InvalidAPIResponseError(
                f"Unexpected action status response shape: {response}"
            )

        api_status_code = transaction.get("apiStatusCode")
        if api_status_code is not None and api_status_code != "null":
            _LOGGER.debug(f"{DOMAIN} - Last action_status: {api_status_code}")

        if transaction.get("apiResult") == "C":
            return ORDER_STATUS.SUCCESS
        elif transaction.get("apiResult") == "P":
            if not synchronous:
                return ORDER_STATUS.PENDING
            else:
                timedelta = dt.datetime.now() - start_time
                time_left = timeout - timedelta.seconds - 10
                time.sleep(10)
                return self.check_action_status(
                    token, vehicle, action_id, synchronous, time_left
                )

        return ORDER_STATUS.FAILED

    def start_charge(self, token: Token, vehicle: Vehicle) -> str:
        url = self.API_URL + "evc/rcstrt"
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)
        data = json.dumps({"pin": token.pin})
        _LOGGER.debug(
            f"{DOMAIN} - Planned start_charge payload {self._mask_sensitive_data(data)}"
        )
        response = self.sessions.post(
            url, headers=headers, data=json.dumps({"pin": token.pin})
        )
        response_headers = response.headers
        response = response.json()

        _LOGGER.debug(f"{DOMAIN} - Received start_charge response {response}")
        self._check_response_for_errors(response)
        return response_headers["transactionId"]

    def stop_charge(self, token: Token, vehicle: Vehicle) -> str:
        url = self.API_URL + "evc/rcstp"
        headers = self.API_HEADERS
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)

        response = self.sessions.post(
            url, headers=headers, data=json.dumps({"pin": token.pin})
        )
        response_headers = response.headers
        response = response.json()

        _LOGGER.debug(f"{DOMAIN} - Received stop_charge response {response}")
        self._check_response_for_errors(response)
        return response_headers["transactionId"]

    def _update_vehicle_properties_charge(
        self, vehicle: Vehicle, state: list[dict[str, Any]]
    ) -> None:
        try:
            if [x["level"] for x in state if x["plugType"] == 1][-1] <= 100:
                vehicle.ev_charge_limits_ac = [
                    x["level"] for x in state if x["plugType"] == 1
                ][-1]
            if [x["level"] for x in state if x["plugType"] == 0][-1] <= 100:
                vehicle.ev_charge_limits_dc = [
                    x["level"] for x in state if x["plugType"] == 0
                ][-1]
        except Exception:
            _LOGGER.debug(f"{DOMAIN} - SOC Levels couldn't be found. May not be an EV.")

    def _get_charge_limits(
        self, token: Token, vehicle: Vehicle
    ) -> list[dict[str, Any]]:
        url = self.API_URL + "evc/selsoc"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id

        response = self.sessions.post(url, headers=headers)
        response = response.json()
        _LOGGER.debug(f"{DOMAIN} - Received get_charge_limits: {response}")

        # Check for errors (including 7602 - access token deleted)
        self._check_response_for_errors(response)

        return cast(list[dict[str, Any]], response["result"])

    def set_charge_limits(
        self, token: Token, vehicle: Vehicle, ac: int, dc: int
    ) -> str:
        url = self.API_URL + "evc/setsoc"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        headers["pAuth"] = self._get_pin_token(token, vehicle)
        # setsoc expects the SPA channel plus portal extras on kiaconnect (Hyundai-Kia-Connect/kia_uvo#957)
        headers["from"] = "SPA"
        if BRANDS[self.brand] != BRAND_HYUNDAI:
            headers["offset"] = "-8"
            headers["priority"] = "u=1, i"
            headers["Referer"] = f"https://{self.BASE_URL}/remote/"

        payload = {
            "tsoc": [
                {
                    "plugType": 0,
                    "level": dc,
                },
                {
                    "plugType": 1,
                    "level": ac,
                },
            ],
            "pin": token.pin,
        }

        _LOGGER.debug(
            f"{DOMAIN} - Planned set_charge_limits payload {self._mask_sensitive_data(payload)}"
        )
        response = self.sessions.post(url, headers=headers, data=json.dumps(payload))
        response_headers = response.headers
        response = response.json()
        _LOGGER.debug(f"{DOMAIN} - Received set_charge_limits response {response}")
        self._check_response_for_errors(response)
        return response_headers["transactionId"]

    def _update_charge_schedule(self, token: Token, vehicle: Vehicle) -> None:
        url = self.API_URL + "v2/rc/ev/getrescharge"
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        headers["vehicleId"] = vehicle.id
        response = self.sessions.get(url, headers=headers)
        if not response.ok:
            _LOGGER.debug(f"{DOMAIN} - getrescharge failed: {response.text}")
            return
        response_json = response.json()
        _LOGGER.debug(f"{DOMAIN} - Received getrescharge response {response_json}")
        if get_child_value(response_json, "responseHeader.responseCode") != 0:
            return  # not every CA EV offers a charge schedule; keep the update
        result = response_json.get("result") or {}
        flag = result.get("reservFlag")
        vehicle.ev_schedule_charge_enabled = None if flag is None else flag == 1
        # Flat-body enum, as on the EU EV5-appMode path: 1 = off-peak only
        mode = result.get("offpeakPowerFlag")
        vehicle.ev_off_peak_charge_only_enabled = (
            True if mode == 1 else False if mode == 2 else None
        )
        vehicle.ev_off_peak_start_time = _reservation_time(
            result.get("reservStartTime")
        )
        vehicle.ev_off_peak_end_time = _reservation_time(result.get("reservEndTime"))

    def schedule_charging_and_climate(
        self,
        token: Token,
        vehicle: Vehicle,
        options: ScheduleChargingClimateRequestOptions,
    ) -> str:
        """Charge window (v2/rc/ev/reschargeset) and departures (v2/rc/ev/reshvacset).

        Each scope is only sent when one of its options was given. When both
        are given, the charge window is written first and the departure
        transaction id is returned.
        """
        charge_active, climate_active = _schedule_charging_scopes(options)
        if not charge_active and not climate_active:
            raise ValueError("no schedule changes requested")
        transaction_id = ""
        if charge_active:
            transaction_id = self._set_charge_window(token, vehicle, options)
        if climate_active:
            transaction_id = self._set_departures(token, vehicle, options)
        return transaction_id

    def _set_charge_window(
        self,
        token: Token,
        vehicle: Vehicle,
        options: ScheduleChargingClimateRequestOptions,
    ) -> str:
        _fill_schedule_options_from_vehicle(options, vehicle, scopes=("charge",))
        start, end = options.off_peak_start_time, options.off_peak_end_time
        assert start is not None and end is not None
        payload = {
            "reservFlag": 1 if options.charging_enabled else 0,
            "offpeakPowerFlag": 1 if options.off_peak_charge_only_enabled else 2,
            "reservStartTime": _reservation_time_body(start),
            "reservEndTime": _reservation_time_body(end),
            "pin": token.pin,
        }
        return self._ca_command(token, vehicle, "v2/rc/ev/reschargeset", payload)

    def _departure_body(
        self,
        vehicle: Vehicle,
        departure: ScheduleChargingClimateRequestOptions.DepartureOptions,
    ) -> dict[str, Any]:
        """One reservedHVACInfo slot, shaped like kiaconnect.ca sends it.

        The portal drops reservHVACSet for a disabled slot and never sends
        heating1 in it.
        """
        days = sorted({d for d in (departure.days or []) if 0 <= d <= 6})
        body: dict[str, Any] = {
            "reservHVACflag": 1 if departure.enabled else 0,
            "reservInfo": {
                "day": days or [_CA_NO_DAY],
                "time": _reservation_time_body(departure.time or dt.time()),
            },
        }
        if departure.enabled:
            table = (
                self.temperature_range_c_new
                if vehicle.year is not None
                and vehicle.year >= self.temperature_range_model_year
                else self.temperature_range_c_old
            )
            temperature = departure.temperature
            if temperature is None or temperature not in table:
                temperature = 21.0
            # getresdetails returns the slot temperature as "23.0" (unit 0);
            # send it back in the same form.
            body["reservHVACSet"] = {
                "airCtrl": 1 if departure.climate_enabled else 0,
                "defrost": bool(departure.defrost),
                "airTemp": {"value": f"{float(temperature):.1f}", "unit": 0},
            }
        return body

    def _set_departures(
        self,
        token: Token,
        vehicle: Vehicle,
        options: ScheduleChargingClimateRequestOptions,
    ) -> str:
        _fill_schedule_options_from_vehicle(options, vehicle, scopes=("climate",))
        assert options.first_departure is not None
        assert options.second_departure is not None
        payload: dict[str, Any] = {
            "pin": token.pin,
            "reservedHVACInfo1": self._departure_body(vehicle, options.first_departure),
            "reservedHVACInfo2": self._departure_body(
                vehicle, options.second_departure
            ),
        }
        return self._ca_command(token, vehicle, "v2/rc/ev/reshvacset", payload)

    # ----- kiaconnect.ca account/vehicle features -------------------------

    def _ca_headers(
        self, token: Token, vehicle: Vehicle | None = None, pin: bool = False
    ) -> dict[str, Any]:
        headers = self.API_HEADERS.copy()
        headers["accessToken"] = token.access_token
        if vehicle is not None:
            headers["vehicleId"] = vehicle.id
            if pin:
                headers["pAuth"] = self._get_pin_token(token, vehicle)
        return headers

    def _ca_call(
        self,
        token: Token,
        vehicle: Vehicle | None,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        method: str = "POST",
        pin: bool = False,
    ) -> tuple[Any, dict[str, Any]]:
        """POST/GET a /tods/api path; returns (response headers, checked JSON)."""
        url = self.API_URL + path
        headers = self._ca_headers(token, vehicle, pin)
        if method == "GET":
            response = self.sessions.get(url, headers=headers)
        else:
            response = self.sessions.post(
                url, headers=headers, data=json.dumps(body or {})
            )
        response_json: dict[str, Any] = response.json()
        _LOGGER.debug(
            f"{DOMAIN} - {path} response {self._mask_sensitive_data(response_json)}"
        )
        self._check_response_for_errors(response_json)
        return response.headers, response_json

    def _ca_command(
        self, token: Token, vehicle: Vehicle, path: str, payload: dict[str, Any]
    ) -> str:
        """A PIN-protected vehicle command; returns the transaction id."""
        _LOGGER.debug(
            f"{DOMAIN} - Planned {path} payload {self._mask_sensitive_data(payload)}"
        )
        headers, response_json = self._ca_call(token, vehicle, path, payload, pin=True)
        return cast(
            str,
            headers.get("transactionId") or response_json.get("transactionid") or "",
        )

    def valet_mode_action(
        self, token: Token, vehicle: Vehicle, action: VALET_MODE_ACTION
    ) -> str:
        """valet/activate | valet/deactivate.

        The endpoints are registered in the kiaconnect.ca bundle but the page
        that calls them is not in the web app, so the body (PIN only, like the
        other remote commands) is inferred.
        """
        path = (
            "valet/activate"
            if action == VALET_MODE_ACTION.ACTIVATE
            else "valet/deactivate"
        )
        return self._ca_command(token, vehicle, path, {"pin": token.pin})

    def set_last_service(
        self,
        token: Token,
        vehicle: Vehicle,
        odometer: float,
        service_date: dt.date,
        dealer_code: str | None = None,
    ) -> str:
        """Reset the service reminder (svcodmt), as the overview page's RESET does."""
        body: dict[str, Any] = {
            "serviceOdometer": odometer,
            "serviceDate": service_date.strftime("%Y%m%d"),
        }
        if dealer_code:
            body["dealerCode"] = dealer_code
        headers, response_json = self._ca_call(token, vehicle, "svcodmt", body)
        return cast(
            str,
            headers.get("transactionId") or response_json.get("transactionid") or "",
        )

    def set_vehicle_nickname(self, token: Token, vehicle: Vehicle, name: str) -> None:
        """chngvhclncknm {vehicleId, newNickname}."""
        self._ca_call(
            token,
            vehicle,
            "chngvhclncknm",
            {"vehicleId": vehicle.id, "newNickname": name},
        )
        vehicle.name = name

    def get_climate_favourites(
        self, token: Token, vehicle: Vehicle
    ) -> list[dict[str, Any]]:
        """Saved climate presets (gtfvsttng): id, settingName, defaultFavorite, ..."""
        _, response_json = self._ca_call(token, vehicle, "gtfvsttng")
        favourites = response_json.get("result") or []
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["climate_favourites"] = favourites
        return cast(list[dict[str, Any]], favourites)

    def save_climate_favourite(
        self, token: Token, vehicle: Vehicle, setting: dict[str, Any]
    ) -> None:
        """svfvsttng {setting}; setting uses the start-climate body keys plus
        id (0 for a new preset) and settingName (max 20 characters)."""
        self._ca_call(token, vehicle, "svfvsttng", {"setting": setting})

    def delete_climate_favourite(
        self, token: Token, vehicle: Vehicle, favourite_id: int
    ) -> None:
        self._ca_call(token, vehicle, "rmfvsttng", {"id": favourite_id})

    def set_default_climate_favourite(
        self, token: Token, vehicle: Vehicle, favourite_id: int
    ) -> None:
        self._ca_call(token, vehicle, "svdefaultfvsttng", {"id": favourite_id})

    def get_monthly_report_day(self, token: Token, vehicle: Vehicle) -> int | None:
        """gtmvrdy -> {"day": "27"}."""
        _, response_json = self._ca_call(token, vehicle, "gtmvrdy")
        day = int_or_none(get_child_value(response_json, "result.day"))
        vehicle.monthly_report_day = day
        return day

    def get_valet_mode(self, token: Token, vehicle: Vehicle) -> bool | None:
        """valet/lastvaletstatus -> {"valetMode": n}.

        A 2026 EV9 that was not in valet mode reported 1 (and vhcllst
        valetParkingModeOn 1), so 1 is read as inactive and 0 as active.
        Note the EU GSPA enum differs (0 active, 1 ign-off, 2 inactive).
        """
        _, response_json = self._ca_call(token, vehicle, "valet/lastvaletstatus")
        mode = get_child_value(response_json, "result.valetMode")
        vehicle.valet_mode_active = False if mode == 1 else True if mode == 0 else None
        return vehicle.valet_mode_active

    def get_preferred_dealer(self, token: Token, vehicle: Vehicle) -> dict[str, Any]:
        """gtprfrdlr (POST): dealerCode, dealerName, address, tel, hours lists."""
        _, response_json = self._ca_call(token, vehicle, "gtprfrdlr")
        dealer = response_json.get("result") or {}
        vehicle.preferred_dealer_name = dealer.get("dealerName")
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["preferred_dealer"] = dealer
        return cast(dict[str, Any], dealer)

    def get_notification_history(
        self, token: Token, vehicle: Vehicle
    ) -> list[dict[str, Any]]:
        """v2/ntfhst -> {"notifications": [...]} for the selected vehicle."""
        _, response_json = self._ca_call(token, vehicle, "v2/ntfhst")
        notifications = get_child_value(response_json, "result.notifications") or []
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["notifications"] = notifications
        return cast(list[dict[str, Any]], notifications)

    def get_unread_message_count(self, token: Token, vehicle: Vehicle) -> int | None:
        """ntcmsgcnt -> {"count": n} (Kia Connect notice messages)."""
        _, response_json = self._ca_call(token, vehicle, "ntcmsgcnt")
        vehicle.unread_message_count = int_or_none(
            get_child_value(response_json, "result.count")
        )
        return vehicle.unread_message_count

    def get_digital_key_status(self, token: Token, vehicle: Vehicle) -> dict[str, Any]:
        """dkc/dkeystatus (GET): ownerDkeyInfo is set once the key is activated."""
        _, response_json = self._ca_call(token, vehicle, "dkc/dkeystatus", method="GET")
        result = response_json.get("result") or {}
        owner = result.get("ownerDkeyInfo")
        vehicle.digital_key_activated = bool(owner and owner.get("id"))
        if vehicle.data is None:
            vehicle.data = {}
        vehicle.data["digital_key"] = result
        return cast(dict[str, Any], result)

    def get_subscription(self, token: Token, vehicle: Vehicle) -> dict[str, Any]:
        """billing/retrieve/account/overview (GET): current Kia Connect package."""
        _, response_json = self._ca_call(
            token, vehicle, "billing/retrieve/account/overview", method="GET"
        )
        package = (
            get_child_value(response_json, "result.currentPackage.currentPackage") or {}
        )
        vehicle.connect_plan_type = package.get("planType")
        vehicle.connect_plan_status = package.get("status")
        end = str(package.get("subscriptionEndDate") or "")[:10].replace("-", "")
        if _ymd_date(end):
            vehicle.connect_subscription_end_date = _ymd_date(end)
        return cast(dict[str, Any], package)

    _CA_EXTRAS_INTERVAL = dt.timedelta(hours=6)

    def _update_account_extras(self, token: Token, vehicle: Vehicle) -> None:
        """Slow-changing kiaconnect.ca data, refreshed at most every 6 hours.

        Each call is independent; one failing never blocks the others or the
        vehicle update.
        """
        if vehicle.data is None:
            vehicle.data = {}
        last = vehicle.data.get("_ca_extras_at")
        now = time.time()
        interval = self._CA_EXTRAS_INTERVAL.total_seconds()
        if isinstance(last, (int, float)) and now - last < interval:
            return
        vehicle.data["_ca_extras_at"] = now
        for fetch in (
            self.get_valet_mode,
            self.get_preferred_dealer,
            self.get_unread_message_count,
            self.get_notification_history,
            self.get_digital_key_status,
            self.get_subscription,
            self.get_climate_favourites,
            self.get_monthly_report_day,
        ):
            try:
                fetch(token, vehicle)
            except Exception as err:
                _LOGGER.debug(f"{DOMAIN} - {fetch.__name__} failed: {err}")

    def set_monthly_report_day(self, token: Token, vehicle: Vehicle, day: int) -> None:
        """Day of the month the Monthly Vehicle Report is generated (svmvrdy)."""
        self._ca_call(token, vehicle, "svmvrdy", {"day": day})

    def _mask_sensitive_data(self, data: dict[str, Any] | str) -> dict[str, Any] | str:
        """Create a copy of data with sensitive fields masked for logging."""
        if isinstance(data, str):
            return data
        import copy

        masked = copy.deepcopy(data)
        sensitive_keys = ["pin", "password"]
        for key in sensitive_keys:
            if key in masked:
                masked[key] = "****"
        return masked
