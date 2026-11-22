"""CA heated steering wheel level and seat heat/vent levels.

kiaconnect.ca sends the wheel level as steerWheelHeat_step2 (0 off, 1 low,
2 high) with a separate sideBackWindowHeat flag, and lstvhclsts reports the
same key back. Seat commands use the portal encoding: 2 + level, plus 3 for
heat (heat 6/7/8 = low/medium/high, vent 3/4/5), reported back unchanged in
status.seatHeaterVentInfo.

Verified on a 2026 EV9 (G3), 2026-11-21:
- steerWheelHeat_step2=2 came back as 2, steerWheelHeat_step2=1 came back as 1.
- drvSeatOptCmd=8, astSeatOptCmd=6, rear 0 came back as drv 8, ast 6, rear 2.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

import pytest

from hyundai_kia_connect_api.ApiImpl import ClimateRequestOptions
from hyundai_kia_connect_api.const import ENGINE_TYPES
from hyundai_kia_connect_api.KiaUvoApiCA import KiaUvoApiCA
from hyundai_kia_connect_api.Token import Token
from hyundai_kia_connect_api.Vehicle import Vehicle
from tests.fixture_helpers import load_fixture

_HEADERS = {"transactionId": "TX-1"}
_BODY = {"responseHeader": {"responseCode": 0}, "result": {"pAuth": "x"}}


def _send(
    engine_type: ENGINE_TYPES, options: ClimateRequestOptions, monkeypatch
) -> dict[str, Any]:
    api = KiaUvoApiCA.__new__(KiaUvoApiCA)
    KiaUvoApiCA.__init__(api, 2, 1, "en")
    sent: dict[str, Any] = {}

    def fake_post(url, headers, payload):
        sent["url"], sent["payload"] = url, payload
        return _HEADERS, dict(_BODY)

    monkeypatch.setattr(api, "_post_start_climate", fake_post)
    monkeypatch.setattr(api, "_get_pin_token", lambda token, vehicle: "pin-auth")
    token = Token(
        username="u",
        password="p",
        pin="1234",
        access_token="a",
        refresh_token="r",
        device_id="d",
        valid_until=dt.datetime.now() + dt.timedelta(hours=1),
    )
    vehicle = Vehicle(
        id="V", year=2026, model="EV9", engine_type=engine_type, generation="G3"
    )
    api.start_climate(token, vehicle, options)
    return sent["payload"]


@pytest.mark.parametrize(
    ("engine_type", "body_key"),
    [(ENGINE_TYPES.EV, "remoteControl"), (ENGINE_TYPES.ICE, "setting")],
)
@pytest.mark.parametrize(
    ("heating", "steering", "side_back"), [(4, 2, 1), (0, 1, 0), (2, 0, 1)]
)
def test_steering_wheel_level_is_sent(
    engine_type, body_key, heating, steering, side_back, monkeypatch
) -> None:
    payload = _send(
        engine_type,
        ClimateRequestOptions(set_temp=22, heating=heating, steering_wheel=steering),
        monkeypatch,
    )
    body = payload[body_key]
    assert body["steerWheelHeat_step2"] == steering
    assert body["sideBackWindowHeat"] == side_back
    assert body["heating1"] == heating


def test_payload_unchanged_without_steering_wheel(monkeypatch) -> None:
    payload = _send(
        ENGINE_TYPES.EV, ClimateRequestOptions(set_temp=22, heating=4), monkeypatch
    )
    assert "steerWheelHeat_step2" not in payload["remoteControl"]
    assert "sideBackWindowHeat" not in payload["remoteControl"]


@pytest.mark.parametrize(("raw", "expected"), [(2, 2), (1, 1), (0, 0), (None, None)])
def test_status_steering_wheel_step(raw, expected) -> None:
    state = load_fixture("updates/responses/ca_kia_lstvhclsts_881.json")["result"]
    if raw is None:
        state["status"].pop("steerWheelHeat_step2", None)
    else:
        state["status"]["steerWheelHeat_step2"] = raw
    api = KiaUvoApiCA.__new__(KiaUvoApiCA)
    api.data_timezone = KiaUvoApiCA.data_timezone
    vehicle = Vehicle(id="test-id")

    api._update_vehicle_properties_base(vehicle, state)

    assert vehicle.steering_wheel_heat_step == expected


def test_seat_levels_are_sent_unchanged(monkeypatch) -> None:
    payload = _send(
        ENGINE_TYPES.EV,
        ClimateRequestOptions(
            set_temp=22,
            heating=4,
            steering_wheel=1,
            front_left_seat=8,
            front_right_seat=6,
            rear_left_seat=0,
            rear_right_seat=0,
        ),
        monkeypatch,
    )
    assert payload["remoteControl"]["seatHeaterVentCMD"] == {
        "drvSeatOptCmd": 8,
        "astSeatOptCmd": 6,
        "rlSeatOptCmd": 0,
        "rrSeatOptCmd": 0,
    }
    assert payload["remoteControl"]["steerWheelHeat_step2"] == 1


def test_status_after_verified_start() -> None:
    """Status the EV9 reported after the seat/wheel start above."""
    state = load_fixture("updates/responses/ca_kia_lstvhclsts_881.json")["result"]
    state["status"]["steerWheelHeat_step2"] = 1
    state["status"]["seatHeaterVentInfo"] = {
        "drvSeatHeatState": 8,
        "astSeatHeatState": 6,
        "rlSeatHeatState": 2,
        "rrSeatHeatState": 2,
    }
    api = KiaUvoApiCA.__new__(KiaUvoApiCA)
    api.data_timezone = KiaUvoApiCA.data_timezone
    vehicle = Vehicle(id="test-id")

    api._update_vehicle_properties_base(vehicle, state)

    assert vehicle.steering_wheel_heat_step == 1
    assert vehicle.front_left_seat_status == "High Heat"
    assert vehicle.front_right_seat_status == "Low Heat"
    assert vehicle.rear_left_seat_status == "Off"
    assert vehicle.rear_right_seat_status == "Off"
