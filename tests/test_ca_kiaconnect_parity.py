"""kiaconnect.ca features: departures, status fields, service, valet, presets.

Status and service fixtures are real captures from a 2026 EV9 (G3), 2026-11-21.
Request bodies follow the kiaconnect.ca web app (main.b8580be0.chunk.js).
"""

from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest

from hyundai_kia_connect_api.ApiImpl import (
    ClimateRequestOptions,
    ScheduleChargingClimateRequestOptions,
)
from hyundai_kia_connect_api.const import ENGINE_TYPES, VALET_MODE_ACTION
from hyundai_kia_connect_api.KiaUvoApiCA import KiaUvoApiCA
from hyundai_kia_connect_api.Token import Token
from hyundai_kia_connect_api.Vehicle import Vehicle
from tests.fixture_helpers import load_fixture

Departure = ScheduleChargingClimateRequestOptions.DepartureOptions


def _api() -> KiaUvoApiCA:
    api = KiaUvoApiCA.__new__(KiaUvoApiCA)
    KiaUvoApiCA.__init__(api, 2, 1, "en")
    return api


def _vehicle() -> Vehicle:
    return Vehicle(
        id="V", year=2026, model="EV9", engine_type=ENGINE_TYPES.EV, generation="G3"
    )


def _token() -> Token:
    return Token(
        username="u",
        password="p",
        pin="1234",
        access_token="a",
        refresh_token="r",
        device_id="d",
        valid_until=dt.datetime.now() + dt.timedelta(hours=1),
    )


class _Response:
    def __init__(self, body: dict[str, Any]) -> None:
        self._body = body
        self.headers = {"transactionId": "TX-1"}
        self.ok = True

    def json(self) -> dict[str, Any]:
        return self._body


@pytest.fixture
def sent(monkeypatch) -> list[dict[str, Any]]:
    """Capture every CA request; answer success."""
    calls: list[dict[str, Any]] = []
    ok = {"responseHeader": {"responseCode": 0}, "result": {"pAuth": "x"}}

    class _Session:
        def post(self, url, headers=None, data=None, json=None, **kw):
            calls.append(
                {"method": "POST", "url": url, "body": data, "headers": headers}
            )
            return _Response(ok)

        def get(self, url, headers=None, **kw):
            calls.append({"method": "GET", "url": url, "headers": headers})
            return _Response(ok)

    monkeypatch.setattr(KiaUvoApiCA, "sessions", property(lambda self: _Session()))
    return calls


def _body(call: dict[str, Any]) -> dict[str, Any]:
    return json.loads(call["body"])


def test_status_fields_from_ev9_capture() -> None:
    state = load_fixture("updates/responses/ca_kia_ev9_lstvhclsts.json")["result"]
    vehicle = _vehicle()
    _api()._update_vehicle_properties_base(vehicle, state)

    assert vehicle.smart_key_battery_warning_is_on is False
    assert vehicle.ev_battery_soh_percentage == 95
    assert vehicle.ev_v2l_discharge_limit == 20
    assert vehicle.steering_wheel_heat_step == 0


def test_departures_from_ev9_capture() -> None:
    state = load_fixture("updates/responses/ca_kia_ev9_lstvhclsts.json")["result"]
    vehicle = _vehicle()
    _api()._update_vehicle_properties_base(vehicle, state)

    assert vehicle.ev_first_departure_enabled is False
    assert vehicle.ev_first_departure_days == [0, 1, 2, 3, 4, 5, 6]
    assert vehicle.ev_first_departure_time == dt.time(5, 20)
    assert vehicle.ev_first_departure_climate_enabled is True
    assert vehicle.ev_first_departure_climate_defrost is True
    assert vehicle.ev_first_departure_climate_temperature == 23.0
    assert vehicle.ev_second_departure_time is None  # "0000" = never set
    assert vehicle.ev_second_departure_climate_temperature == 20.0


def test_departure_hex_temperature() -> None:
    api = _api()
    assert api._departure_temperature(_vehicle(), "10H") == 22.0
    assert api._departure_temperature(_vehicle(), "23.0") == 23.0
    assert api._departure_temperature(_vehicle(), None) is None


def test_service_dates_from_ev9_capture() -> None:
    state = load_fixture("updates/responses/ca_kia_ev9_nxtsvc.json")["result"][
        "maintenanceInfo"
    ]
    vehicle = _vehicle()
    _api()._update_vehicle_properties_service(vehicle, state)

    assert vehicle.next_service_date == dt.date(2027, 3, 27)
    assert vehicle.last_service_date == dt.date(2026, 3, 27)
    assert vehicle.service_interval_distance == 13000.0
    assert vehicle.service_interval_months == 12


def test_set_departures_body(sent) -> None:
    vehicle = _vehicle()
    options = ScheduleChargingClimateRequestOptions(
        first_departure=Departure(
            enabled=True,
            days=[1, 2, 3, 4, 5],
            time=dt.time(6, 45),
            climate_enabled=True,
            temperature=22.0,
            defrost=True,
        ),
        second_departure=Departure(
            enabled=False,
            days=[],
            time=dt.time(0, 0),
            climate_enabled=False,
            temperature=21.0,
            defrost=False,
        ),
    )
    assert _api().schedule_charging_and_climate(_token(), vehicle, options) == "TX-1"
    call = sent[-1]
    assert call["url"].endswith("v2/rc/ev/reshvacset")
    assert call["headers"]["pAuth"] == "x"
    body = _body(call)
    assert body["reservedHVACInfo1"] == {
        "reservHVACflag": 1,
        "reservInfo": {
            "day": [1, 2, 3, 4, 5],
            "time": {"time": "0645", "timeSection": 0},
        },
        "reservHVACSet": {
            "airCtrl": 1,
            "defrost": True,
            "airTemp": {"value": "22.0", "unit": 0},
        },
    }
    # Disabled slot: no reservHVACSet, "no day" marker
    assert body["reservedHVACInfo2"] == {
        "reservHVACflag": 0,
        "reservInfo": {"day": [9], "time": {"time": "1200", "timeSection": 0}},
    }


def test_charge_and_departure_together(sent) -> None:
    options = ScheduleChargingClimateRequestOptions(
        charging_enabled=True,
        off_peak_start_time=dt.time(23, 0),
        off_peak_end_time=dt.time(7, 0),
        off_peak_charge_only_enabled=True,
        first_departure=Departure(enabled=False),
    )
    _api().schedule_charging_and_climate(_token(), _vehicle(), options)
    urls = [c["url"] for c in sent if c["url"].endswith(("set", "chargeset"))]
    assert urls[0].endswith("v2/rc/ev/reschargeset")
    assert urls[-1].endswith("v2/rc/ev/reshvacset")


def test_no_schedule_options_raises() -> None:
    with pytest.raises(ValueError):
        _api().schedule_charging_and_climate(
            _token(), _vehicle(), ScheduleChargingClimateRequestOptions()
        )


@pytest.mark.parametrize(
    ("action", "path"),
    [
        (VALET_MODE_ACTION.ACTIVATE, "valet/activate"),
        (VALET_MODE_ACTION.DEACTIVATE, "valet/deactivate"),
    ],
)
def test_valet_mode(sent, action, path) -> None:
    assert _api().valet_mode_action(_token(), _vehicle(), action) == "TX-1"
    assert sent[-1]["url"].endswith(path)
    assert _body(sent[-1]) == {"pin": "1234"}
    assert sent[-1]["headers"]["pAuth"] == "x"


def test_set_last_service(sent) -> None:
    _api().set_last_service(_token(), _vehicle(), 27044.4, dt.date(2026, 11, 21))
    assert sent[-1]["url"].endswith("svcodmt")
    assert _body(sent[-1]) == {"serviceOdometer": 27044.4, "serviceDate": "20261121"}


def test_set_vehicle_nickname(sent) -> None:
    vehicle = _vehicle()
    _api().set_vehicle_nickname(_token(), vehicle, "EV9 Family")
    assert _body(sent[-1]) == {"vehicleId": "V", "newNickname": "EV9 Family"}
    assert vehicle.name == "EV9 Family"


def test_climate_favourite_calls(sent) -> None:
    api, token, vehicle = _api(), _token(), _vehicle()
    api.save_climate_favourite(
        token,
        vehicle,
        "Max heat for the whole family",
        ClimateRequestOptions(
            set_temp=22.0, heating=4, steering_wheel=2, front_left_seat=8
        ),
    )
    api.delete_climate_favourite(token, vehicle, 3)
    api.set_default_climate_favourite(token, vehicle, 2)
    api.set_monthly_report_day(token, vehicle, 15)
    paths = [c["url"].rsplit("/", 1)[-1] for c in sent]
    assert paths == ["svfvsttng", "rmfvsttng", "svdefaultfvsttng", "svmvrdy"]
    setting = _body(sent[0])["setting"]
    assert setting["id"] == 0
    assert setting["settingName"] == "Max heat for the whol"[:20]
    assert setting["airTemp"] == {"value": "10H", "unit": 0, "hvacTempType": 1}
    assert setting["steerWheelHeat_step2"] == 2
    assert setting["sideBackWindowHeat"] == 1
    assert setting["seatHeaterVentCMD"]["drvSeatOptCmd"] == 8
    assert _body(sent[1]) == {"id": 3}
    assert _body(sent[3]) == {"day": 15}


def _ok(result: Any) -> dict[str, Any]:
    return {"responseHeader": {"responseCode": 0}, "result": result}


@pytest.fixture
def reply(monkeypatch):
    """Answer each CA path with a canned result (captures from kiaconnect.ca)."""
    answers: dict[str, Any] = {}

    class _Session:
        def post(self, url, headers=None, data=None, json=None, **kw):
            return _Response(_ok(answers.get(url.split("/tods/api/")[-1])))

        def get(self, url, headers=None, **kw):
            return _Response(_ok(answers.get(url.split("/tods/api/")[-1])))

    monkeypatch.setattr(KiaUvoApiCA, "sessions", property(lambda self: _Session()))
    return answers


def test_account_extras(reply) -> None:
    reply.update(
        {
            "valet/lastvaletstatus": {"vehicleId": "V", "valetMode": 1},
            "gtprfrdlr": {"dealerCode": "53069", "dealerName": "Dealer"},
            "ntcmsgcnt": {"count": 2},
            "v2/ntfhst": {"vehicleId": "V", "notifications": [{"a": 1}]},
            "dkc/dkeystatus": {"vehicleId": "V", "ownerDkeyInfo": None},
            "billing/retrieve/account/overview": {
                "currentPackage": {
                    "currentPackage": {
                        "status": "Active",
                        "planType": "Trial",
                        "subscriptionEndDate": "2029-03-21 00:00:00",
                    }
                }
            },
            "gtfvsttng": [{"id": 1, "settingName": "Warm", "defaultFavorite": True}],
            "gtmvrdy": {"day": "27"},
        }
    )
    api, vehicle = _api(), _vehicle()
    api._update_account_extras(_token(), vehicle)

    assert vehicle.valet_mode_active is False
    assert vehicle.preferred_dealer_name == "Dealer"
    assert vehicle.unread_message_count == 2
    assert vehicle.data["notifications"] == [{"a": 1}]
    assert vehicle.digital_key_activated is False
    assert vehicle.connect_plan_type == "Trial"
    assert vehicle.connect_plan_status == "Active"
    assert vehicle.connect_subscription_end_date == dt.date(2029, 3, 21)
    assert vehicle.data["climate_favourites"][0]["settingName"] == "Warm"
    assert vehicle.monthly_report_day == 27

    # Throttled: a second call within 6 hours does nothing
    reply["ntcmsgcnt"] = {"count": 9}
    api._update_account_extras(_token(), vehicle)
    assert vehicle.unread_message_count == 2


def test_account_extras_survive_failures(monkeypatch) -> None:
    def boom(*a, **k):
        raise RuntimeError("nope")

    monkeypatch.setattr(KiaUvoApiCA, "_ca_call", boom)
    vehicle = _vehicle()
    _api()._update_account_extras(_token(), vehicle)  # must not raise
    assert vehicle.preferred_dealer_name is None


def test_charge_limits_use_socset_for_ccs2(sent) -> None:
    """Gen3/CCS2 cars use v2/ev/reserv/socset like kiaconnect.ca does."""
    tx = _api().set_charge_limits(_token(), _vehicle(), ac=90, dc=100)
    assert tx == "TX-1"
    call = sent[-1]
    assert call["url"].endswith("v2/ev/reserv/socset")
    assert call["headers"]["pAuth"] == "x"
    assert _body(call) == {
        "pin": "1234",
        "targetSOClist": [
            {"plugType": 0, "targetSOClevel": 100},
            {"plugType": 1, "targetSOClevel": 90},
        ],
    }


def test_charge_limits_keep_setsoc_for_older_generations(sent) -> None:
    vehicle = _vehicle()
    vehicle.generation = "G2"
    _api().set_charge_limits(_token(), vehicle, ac=80, dc=70)
    assert sent[-1]["url"].endswith("evc/setsoc")
