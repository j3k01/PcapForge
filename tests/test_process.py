import pytest

from pcapforge.process import TABLES, ProcessProfile, ProcessSim
from pcapforge.profiles import PROFILE_DIR
from pcapforge.rng import Rng

PROFILES = sorted(path.stem for path in (PROFILE_DIR / "processes").glob("*.yaml"))
BACKGROUND_PROFILES = ("wastewater_treatment", "hvac_building", "power_substation")


def make_sim():
    return ProcessSim(ProcessProfile("water_treatment"), Rng("test"), start_hour=10.0)


def test_setpoint_write_drives_measurement_and_alarm_over_time():
    sim = make_sim()
    profile = sim.profile
    dose = profile.by_name["chlorine_dose_sp"]
    residual = profile.by_name["chlorine_residual"]
    alarm = profile.by_name["chlorine_high"]
    before = sim.read("input")[residual.address]
    assert sim.read("discrete")[alarm.address] == 0

    sim.write("holding", dose.address, [dose.encode(9.0)])
    sim.advance(60)
    early = sim.read("input")[residual.address]
    sim.advance(3600)
    late = sim.read("input")[residual.address]

    assert before < early < late
    assert sim.read("discrete")[alarm.address] == 1


def test_writes_to_read_only_points_are_ignored():
    sim = make_sim()
    level = sim.profile.by_name["clearwell_level"]
    sim.write("input", level.address, [999])
    assert sim.value("clearwell_level") != 999


def test_counters_wrap_like_16_bit_registers():
    point = ProcessProfile("water_treatment").by_name["treated_volume_m3"]
    assert point.encode(65536 + 5) == 5


def _sources(model: dict) -> list[str]:
    if model["type"] == "follow":
        return [model["source"]] + [extra["source"] for extra in model.get("inputs", ())]
    if model["type"] in ("above", "below"):
        return [model["a"]] + ([model["b"]] if isinstance(model["b"], str) else [])
    return []


@pytest.mark.parametrize("name", PROFILES)
def test_profile_references_resolve(name):
    profile = ProcessProfile(name)
    # The simulator evaluates points in table order, so a follow model must come after its
    # sources or its initial value and every update would lag one step behind.
    order = {p.name: i for i, p in enumerate(profile.points)}
    for table in TABLES:
        addresses = [p.address for p in profile.table(table)]
        assert addresses == list(range(len(addresses))), table
    for point in profile.points:
        if not point.model:
            continue
        for source in _sources(point.model):
            assert [p.name for p in profile.points].count(source) == 1, f"{point.name}: ambiguous {source}"
            if point.model["type"] == "follow":
                assert order[source] < order[point.name], f"{point.name} evaluated before {source}"
        if point.model["type"] == "walk":
            assert point.normal, point.name
    for group in profile.poll_groups:
        assert group["start"] + group["count"] <= profile.size(
            {1: "coils", 2: "discrete", 3: "holding", 4: "input"}[group["function"]])
    for choice in profile.operator_adjustable:
        point = profile.by_name[choice["name"]]
        assert point.table == "holding" and point.writable and point.normal


@pytest.mark.parametrize("name", PROFILES)
def test_every_point_has_a_description_and_a_vendor_register_label(name):
    profile = ProcessProfile(name)
    assert all(p.desc for p in profile.points), [p.name for p in profile.points if not p.desc]
    # The handout numbers registers in the vendor (Modicon) convention; the wire stays 0-based.
    style = profile.register_style
    assert style == {"coils": 1, "discrete": 10001, "input": 30001, "holding": 40001}
    for point in profile.points:
        assert profile.register_label(point) == str(style[point.table] + point.address)


def test_register_label_falls_back_to_the_wire_address_without_a_style():
    profile = ProcessProfile(PROFILES[0])
    profile.register_style = {}  # a profile that defines no vendor numbering
    for point in profile.points:
        assert profile.register_label(point) == str(point.address)


@pytest.mark.parametrize("start_hour", [0.0, 7.0, 13.0, 19.0])
@pytest.mark.parametrize("name", BACKGROUND_PROFILES)
def test_background_process_stays_in_band_for_two_hours(name, start_hour):
    profile = ProcessProfile(name)
    for seed in ("site-a", "site-b"):
        sim = ProcessSim(profile, Rng(seed), start_hour=start_hour)
        for t in range(0, 7201, 20):
            sim.advance(t)
            for table in TABLES:
                for address, raw in sim.read(table).items():
                    point = profile.by_address[(table, address)]
                    value = point.decode(raw)
                    where = f"{point.name} = {value} at t={t}s"
                    if table in ("coils", "discrete"):
                        # No alarm or status change without an operator or attacker write.
                        assert value == point.nominal, where
                        continue
                    if point.model and point.model["type"] == "counter":
                        continue
                    assert point.normal, f"{point.name} has no normal band"
                    assert point.in_normal(value), where
                    assert 0 < raw < 65535, where
                    if point.unit == "%":
                        assert 0 <= value <= 100, where


# (profile, setpoint, value written outside its band, measurement, direction, alarm bit)
SETPOINT_RESPONSES = [
    ("wastewater_treatment", "do_sp", 4.0, "dissolved_oxygen", 1, None),
    ("wastewater_treatment", "do_sp", 0.5, "ammonia", 1, None),
    ("wastewater_treatment", "ras_flow_sp", 60, "sludge_blanket_level", 1, None),
    ("hvac_building", "zone1_temp_sp", 30.0, "zone1_temp", 1, "zone1_high_temp"),
    ("hvac_building", "zone1_temp_sp", 16.0, "zone1_fcu_valve", 1, None),
    ("hvac_building", "chw_supply_temp_sp", 4.0, "chiller_load", 1, None),
    ("power_substation", "tap_position_sp", 17, "bus_voltage", 1, "voltage_high"),
    ("power_substation", "tap_position_sp", 1, "bus_voltage", -1, "voltage_low"),
]


@pytest.mark.parametrize("name,setpoint,value,measurement,direction,alarm", SETPOINT_RESPONSES)
def test_out_of_band_setpoint_moves_dependent_measurement(name, setpoint, value, measurement, direction, alarm):
    profile = ProcessProfile(name)
    point = profile.by_name[setpoint]
    assert not point.in_normal(value)
    baseline = ProcessSim(profile, Rng("response"), start_hour=10.0)
    sim = ProcessSim(profile, Rng("response"), start_hour=10.0)
    sim.write("holding", point.address, [point.encode(value)])
    for t in range(0, 1801, 10):
        baseline.advance(t)
        sim.advance(t)
    lo, hi = profile.by_name[measurement].normal
    # Against the same plant left alone, the shift is a sizeable part of the normal band.
    assert (sim.value(measurement) - baseline.value(measurement)) * direction > 0.1 * (hi - lo)
    if alarm:
        assert baseline.value(alarm) == 0 and sim.value(alarm) == 1
