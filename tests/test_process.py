from pcapforge.process import ProcessProfile, ProcessSim
from pcapforge.rng import Rng


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
